<?php
/**
 * Safe fetch of one URL on the site's own host.
 *
 * Redirects are followed by hand so every hop is re-checked against the URL
 * policy and the resolved address (F1). The connection is pinned to the
 * address that was checked (F2). Size, time and retry limits bound the cost
 * on a shared server (F3). No cookies or credentials are ever sent (F7).
 *
 * @package MLT\SchemaAudit
 */

namespace MLT\SchemaAudit\Engine;

defined( 'ABSPATH' ) || defined( 'MLTSA_TESTING' ) || exit;

/**
 * Fetcher.
 */
class Fetcher {

	/**
	 * Default limits (contract section 4, all Proposed).
	 *
	 * @var array
	 */
	const DEFAULTS = array(
		'timeout'       => 15,
		'max_bytes'     => 5242880,
		'max_redirects' => 5,
		'retries'       => 2,
		'backoff'       => 2,
		'user_agent'    => 'MLT-Schema-Audit',
	);

	/**
	 * Seconds a worker slice keeps beyond one full request, for the work
	 * around it (storing the page, saving progress).
	 *
	 * @var int
	 */
	const MIN_REQUEST_SECONDS = 2;

	/**
	 * URL policy.
	 *
	 * @var UrlPolicy
	 */
	private $policy;

	/**
	 * Transport.
	 *
	 * @var HttpClient
	 */
	private $client;

	/**
	 * Limits.
	 *
	 * @var array
	 */
	private $limits;

	/**
	 * Sleep callable (seconds), injectable so tests do not wait.
	 *
	 * @var callable
	 */
	private $sleep;

	/**
	 * Constructor.
	 *
	 * @param UrlPolicy     $policy URL policy.
	 * @param HttpClient    $client Transport.
	 * @param array         $limits Overrides for DEFAULTS.
	 * @param callable|null $sleep  Sleep function.
	 */
	public function __construct( UrlPolicy $policy, HttpClient $client, array $limits = array(), $sleep = null ) {
		$this->policy = $policy;
		$this->client = $client;
		$this->limits = array_merge( self::DEFAULTS, $limits );
		$this->sleep  = is_callable( $sleep ) ? $sleep : 'sleep';
	}

	/**
	 * Fetch a URL.
	 *
	 * Outcomes: ok, blocked, timeout, too_large, http_error, not_found, gone,
	 * unavailable, redirect_limit, error, deferred.
	 *
	 * With a deadline, no request outlives it, and none is cut short: a
	 * request (or a retry, with its wait) starts only when the time left
	 * covers the full timeout setting. One there was no time left to make or
	 * retry is "deferred" (reason budget_spent, or budget_retry while a
	 * retry's wait has not passed), so the caller can try it again in a later
	 * slice. A timeout is therefore always the site taking longer than the
	 * setting (branch review R1).
	 *
	 * A deferred result carries 'resume': the redirect hop, retry and wait it
	 * stopped at. Passed back in a later call for the same URL and method,
	 * the fetch continues from there instead of starting again, so a redirect
	 * chain or retries longer than one slice are read across slices, each
	 * request with the full timeout (branch review S1). 'attempts' counts the
	 * requests made in this call only.
	 *
	 * @param string $url         Absolute URL.
	 * @param string $method      GET or HEAD.
	 * @param bool   $is_resource True for an image or logo check (wider path policy, every hop).
	 * @param float  $deadline    Unix time (microtime) to finish by; 0 for none.
	 * @param array  $resume      'resume' of an earlier deferred result; ignored unless for this URL and method.
	 * @return array
	 */
	public function fetch( $url, $method = 'GET', $is_resource = false, $deadline = 0.0, array $resume = array() ) {
		$started = microtime( true );
		$result  = array(
			'requested_url' => (string) $url,
			'final_url'     => (string) $url,
			'chain'         => array(),
			'status'        => 0,
			'outcome'       => 'error',
			'reason'        => '',
			'body'          => '',
			'headers'       => array(),
			'content_type'  => '',
			'response_hash' => '',
			'attempts'      => 0,
			'duration_ms'   => 0,
		);

		$current    = (string) $url;
		$first_hop  = 0;
		$first_try  = 0;
		$not_before = 0.0;
		$prior      = 0;
		if ( $this->resumable( $resume, $url, $method ) ) {
			$current             = (string) $resume['current'];
			$first_hop           = (int) $resume['hop'];
			$first_try           = (int) $resume['try'];
			$not_before          = (float) $resume['not_before'];
			$prior               = (int) $resume['attempts'];
			$result['chain']     = (array) $resume['chain'];
			$result['final_url'] = $current;
			$result['status']    = (int) $resume['status'];
		}
		for ( $hop = $first_hop; $hop <= (int) $this->limits['max_redirects']; $hop++ ) {
			$check = $this->policy->check_url( $current, $is_resource );
			if ( ! $check['ok'] ) {
				return $this->finish( $result, 'blocked', $check['reason'], $started );
			}
			$host    = (string) parse_url( $current, PHP_URL_HOST ); // phpcs:ignore WordPress.WP.AlternativeFunctions.parse_url_parse_url
			$address = $this->policy->check_host_addresses( $host );
			if ( ! $address['ok'] ) {
				return $this->finish( $result, 'dns_failure' === $address['reason'] ? 'unavailable' : 'blocked', $address['reason'], $started );
			}

			$response   = $this->request_with_retries( $current, $address['ip'], $method, $result, (float) $deadline, $first_try, $not_before );
			$first_try  = 0;
			$not_before = 0.0;
			if ( 'deferred' === $response['error_code'] ) {
				$result['resume'] = array(
					'url'        => (string) $url,
					'method'     => (string) $method,
					'current'    => $current,
					'hop'        => $hop,
					'try'        => (int) $response['try'],
					'not_before' => (float) $response['not_before'],
					'status'     => (int) $result['status'],
					'chain'      => $result['chain'],
					'attempts'   => $prior + (int) $result['attempts'],
				);
				return $this->finish( $result, 'deferred', $response['reason'], $started );
			}
			if ( '' !== $response['error_code'] ) {
				$outcome = 'timeout' === $response['error_code'] ? 'timeout' : ( 'no_pinning_transport' === $response['error_code'] ? 'unavailable' : 'error' );
				return $this->finish( $result, $outcome, $response['error_code'], $started );
			}

			$status              = (int) $response['status'];
			$result['chain'][]   = array(
				'url'    => $current,
				'status' => $status,
			);
			$result['status']    = $status;
			$result['final_url'] = $current;

			if ( $status >= 300 && $status < 400 && isset( $response['headers']['location'] ) ) {
				$next = UrlPolicy::resolve_reference( $current, $response['headers']['location'] );
				if ( preg_match( '/^([^#]*)#/', $next, $m ) ) {
					$next = $m[1];
				}
				$current = $next;
				continue;
			}

			$result['headers']      = $response['headers'];
			$result['content_type'] = isset( $response['headers']['content-type'] ) ? strtolower( $response['headers']['content-type'] ) : '';

			// The size cap applies to bodies: a HEAD answer has none, and a 2xx
			// answer to it proves the file exists however large it is (R3).
			if ( ! empty( $response['truncated'] ) && 'HEAD' !== $method ) {
				return $this->finish( $result, 'too_large', 'response_over_' . (int) $this->limits['max_bytes'] . '_bytes', $started );
			}
			if ( 401 === $status || 403 === $status ) {
				// Behind basic auth or a security tool: recorded, never given credentials.
				return $this->finish( $result, 'unavailable', 'http_' . $status, $started );
			}
			if ( 404 === $status ) {
				return $this->finish( $result, 'not_found', 'http_404', $started );
			}
			if ( 410 === $status ) {
				return $this->finish( $result, 'gone', 'http_410', $started );
			}
			if ( $status < 200 || $status >= 300 ) {
				return $this->finish( $result, 'http_error', 'http_' . $status, $started );
			}

			$result['body']          = (string) $response['body'];
			$result['response_hash'] = hash( 'sha256', $result['body'] );
			return $this->finish( $result, 'ok', '', $started );
		}

		return $this->finish( $result, 'redirect_limit', 'more_than_' . (int) $this->limits['max_redirects'] . '_redirects', $started );
	}

	/**
	 * Whether a deferred result counts toward the caller's limit of three:
	 * only when the URL had the whole slice ($fair) and still no request
	 * could start. A deferral after a request has moved the fetch on (the
	 * resume state continues from there, and a fetch makes a bounded number
	 * of requests); one waiting for a retry's backoff ends as time passes;
	 * one without the whole slice has it next time. So a URL is never given
	 * up while it is being read, and a run always ends (branch review S1).
	 *
	 * @param array $result Deferred fetch result.
	 * @param bool  $fair   Whether the URL had the whole slice.
	 * @return bool
	 */
	public static function deferral_counts( array $result, $fair ) {
		return (bool) $fair && 0 === (int) $result['attempts'] && 'budget_retry' !== $result['reason'];
	}

	/**
	 * Whether a resume state belongs to this fetch and is within the limits.
	 *
	 * @param array  $resume Resume state.
	 * @param string $url    URL.
	 * @param string $method Method.
	 * @return bool
	 */
	private function resumable( array $resume, $url, $method ) {
		foreach ( array( 'url', 'method', 'current', 'hop', 'try', 'not_before', 'status', 'chain', 'attempts' ) as $key ) {
			if ( ! array_key_exists( $key, $resume ) ) {
				return false;
			}
		}
		return (string) $url === $resume['url'] && (string) $method === $resume['method']
			&& (int) $resume['hop'] >= 0 && (int) $resume['hop'] <= (int) $this->limits['max_redirects']
			&& (int) $resume['try'] >= 0 && (int) $resume['try'] <= max( 0, (int) $this->limits['retries'] );
	}

	/**
	 * One hop, retried for transient failures with backoff.
	 *
	 * @param string $url        URL.
	 * @param string $ip         Pinned address.
	 * @param string $method     Method.
	 * @param array  $result     Result being built (attempt count updated).
	 * @param float  $deadline   Unix time to finish by; 0 for none.
	 * @param int    $first_try  Try to start at (a resumed retry).
	 * @param float  $not_before Unix time before which that try must not start (its backoff).
	 * @return array Response; a deferral adds the try and wait to resume at.
	 */
	private function request_with_retries( $url, $ip, $method, array &$result, $deadline, $first_try = 0, $not_before = 0.0 ) {
		$empty   = array(
			'status'     => 0,
			'headers'    => array(),
			'body'       => '',
			'error_code' => '',
			'truncated'  => false,
			'reason'     => '',
		);
		$tries   = 1 + max( 0, (int) $this->limits['retries'] );
		$timeout = (int) $this->limits['timeout'];
		for ( $i = (int) $first_try; $i < $tries; $i++ ) {
			$wait = $not_before > 0 ? max( 0, (int) ceil( $not_before - microtime( true ) ) ) : 0;
			if ( $deadline > 0 && microtime( true ) + $wait + $timeout > $deadline ) {
				// Not enough time left for the wait and the full timeout:
				// never shorten it. The caller resumes at this try.
				return array_merge(
					$empty,
					array(
						'error_code' => 'deferred',
						'reason'     => $wait > 0 ? 'budget_retry' : 'budget_spent',
						'try'        => $i,
						'not_before' => $not_before,
					)
				);
			}
			if ( $wait > 0 ) {
				call_user_func( $this->sleep, $wait );
			}
			++$result['attempts'];
			$response  = $this->client->request(
				$url,
				$ip,
				array(
					'timeout'    => $timeout,
					'max_bytes'  => $this->limits['max_bytes'],
					'user_agent' => $this->limits['user_agent'],
					'method'     => $method,
				)
			);
			$response  = array_merge( $empty, $response );
			$transient = in_array( $response['error_code'], array( 'transport_error' ), true )
				|| in_array( (int) $response['status'], array( 429, 502, 503, 504 ), true );
			// A timeout is not retried: the page has already held a worker for
			// the full timeout, and retrying would double the load.
			if ( ! $transient || $i === $tries - 1 ) {
				return $response;
			}
			$not_before = microtime( true ) + (int) $this->limits['backoff'] * ( $i + 1 );
		}
		return array_merge( $empty, array( 'error_code' => 'error' ) );
	}

	/**
	 * Complete a result.
	 *
	 * @param array  $result  Result.
	 * @param string $outcome Outcome.
	 * @param string $reason  Reason code.
	 * @param float  $started Start time.
	 * @return array
	 */
	private function finish( array $result, $outcome, $reason, $started ) {
		$result['outcome']     = $outcome;
		$result['reason']      = $reason;
		$result['duration_ms'] = (int) round( ( microtime( true ) - $started ) * 1000 );
		if ( 'ok' !== $outcome ) {
			$result['body'] = '';
		}
		return $result;
	}
}
