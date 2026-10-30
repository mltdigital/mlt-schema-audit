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
	 * unavailable, redirect_limit, error.
	 *
	 * @param string $url    Absolute URL.
	 * @param string $method GET or HEAD.
	 * @return array
	 */
	public function fetch( $url, $method = 'GET' ) {
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

		$current = (string) $url;
		for ( $hop = 0; $hop <= (int) $this->limits['max_redirects']; $hop++ ) {
			$check = $this->policy->check_url( $current );
			if ( ! $check['ok'] ) {
				return $this->finish( $result, 'blocked', $check['reason'], $started );
			}
			$host    = (string) parse_url( $current, PHP_URL_HOST ); // phpcs:ignore WordPress.WP.AlternativeFunctions.parse_url_parse_url
			$address = $this->policy->check_host_addresses( $host );
			if ( ! $address['ok'] ) {
				return $this->finish( $result, 'dns_failure' === $address['reason'] ? 'unavailable' : 'blocked', $address['reason'], $started );
			}

			$response = $this->request_with_retries( $current, $address['ip'], $method, $result );
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

			if ( ! empty( $response['truncated'] ) ) {
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
	 * One hop, retried for transient failures with backoff.
	 *
	 * @param string $url    URL.
	 * @param string $ip     Pinned address.
	 * @param string $method Method.
	 * @param array  $result Result being built (attempt count updated).
	 * @return array
	 */
	private function request_with_retries( $url, $ip, $method, array &$result ) {
		$tries = 1 + max( 0, (int) $this->limits['retries'] );
		for ( $i = 0; $i < $tries; $i++ ) {
			++$result['attempts'];
			$response  = $this->client->request(
				$url,
				$ip,
				array(
					'timeout'    => $this->limits['timeout'],
					'max_bytes'  => $this->limits['max_bytes'],
					'user_agent' => $this->limits['user_agent'],
					'method'     => $method,
				)
			);
			$response  = array_merge(
				array(
					'status'     => 0,
					'headers'    => array(),
					'body'       => '',
					'error_code' => '',
					'truncated'  => false,
				),
				$response
			);
			$transient = in_array( $response['error_code'], array( 'transport_error' ), true )
				|| in_array( (int) $response['status'], array( 429, 502, 503, 504 ), true );
			// A timeout is not retried: the page has already held a worker for
			// the full timeout, and retrying would double the load.
			if ( ! $transient || $i === $tries - 1 ) {
				return $response;
			}
			call_user_func( $this->sleep, (int) $this->limits['backoff'] * ( $i + 1 ) );
		}
		return $response;
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
