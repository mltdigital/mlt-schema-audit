<?php
/**
 * WordPress transport: wp_safe_remote_get() with redirects off, no cookies,
 * no auth headers, a size cap, and cURL resolve pinning (threat model F1, F2, F7).
 *
 * @package MLT\SchemaAudit
 */

namespace MLT\SchemaAudit\Engine;

defined( 'ABSPATH' ) || exit;

/**
 * HttpClient backed by the WordPress HTTP API.
 */
class WpHttpClient implements HttpClient {

	/**
	 * The resolve entry applied by the last request, for tests and the health screen.
	 *
	 * @var string
	 */
	public $last_pin = '';

	/**
	 * Whether the site's own host may be on a loopback or private address
	 * (MLTSA_ALLOW_PRIVATE_SELF, local development only), as UrlPolicy is told.
	 *
	 * @var bool
	 */
	private $allow_private_self;

	/**
	 * Constructor.
	 *
	 * @param bool|null $allow_private_self Null reads MLTSA_ALLOW_PRIVATE_SELF.
	 */
	public function __construct( $allow_private_self = null ) {
		$this->allow_private_self = null === $allow_private_self
			? ( defined( 'MLTSA_ALLOW_PRIVATE_SELF' ) && MLTSA_ALLOW_PRIVATE_SELF )
			: (bool) $allow_private_self;
	}

	/**
	 * {@inheritDoc}
	 *
	 * @param string $url       Absolute URL.
	 * @param string $pinned_ip Address the connection must use.
	 * @param array  $args      Request arguments.
	 * @return array
	 */
	public function request( $url, $pinned_ip, array $args ) {
		$result = array(
			'status'     => 0,
			'headers'    => array(),
			'body'       => '',
			'error'      => '',
			'error_code' => '',
			'pinned'     => false,
			'truncated'  => false,
		);

		if ( ! function_exists( 'curl_init' ) ) {
			// Without cURL the connection cannot be pinned to the checked
			// address, so a DNS rebinding attack could not be ruled out.
			$result['error']      = 'cURL is not available, so the connection cannot be pinned.';
			$result['error_code'] = 'no_pinning_transport';
			return $result;
		}

		$parts = wp_parse_url( $url );
		$host  = isset( $parts['host'] ) ? $parts['host'] : '';
		$port  = isset( $parts['port'] ) ? (int) $parts['port'] : ( 'https' === strtolower( (string) $parts['scheme'] ) ? 443 : 80 );
		$ip    = false !== strpos( $pinned_ip, ':' ) ? '[' . $pinned_ip . ']' : $pinned_ip;
		$pin   = $host . ':' . $port . ':' . $ip;

		$this->last_pin = '';
		$applied        = false;
		$pinner         = function ( $handle ) use ( $pin, &$applied ) {
			// phpcs:ignore WordPress.WP.AlternativeFunctions.curl_curl_setopt -- Pinning needs the raw handle; the HTTP API exposes it for exactly this.
			curl_setopt( $handle, CURLOPT_RESOLVE, array( $pin ) );
			$applied        = true;
			$this->last_pin = $pin;
		};
		add_action( 'http_api_curl', $pinner, PHP_INT_MAX );

		// WordPress checks the URL again (wp_http_validate_url) and exempts
		// only the home host itself from its private-address and port rules,
		// so it refused the www or bare variant that UrlPolicy allows. Give
		// that variant the same exemption, only where a private own host is
		// allowed and only while the connection is pinned to a loopback or
		// private address (never link-local or metadata).
		$variant  = $this->private_variant( $host, $pinned_ip );
		$home     = wp_parse_url( (string) get_option( 'home' ) );
		$external = static function ( $is_external, $checked ) use ( $variant ) {
			return $is_external || ( '' !== $variant && strtolower( (string) $checked ) === $variant );
		};
		$ports    = static function ( $allowed, $checked ) use ( $variant, $home ) {
			if ( '' !== $variant && strtolower( (string) $checked ) === $variant && isset( $home['port'] ) && is_array( $allowed ) ) {
				$allowed[] = (int) $home['port'];
			}
			return $allowed;
		};
		add_filter( 'http_request_host_is_external', $external, PHP_INT_MAX, 2 );
		add_filter( 'http_allowed_safe_ports', $ports, PHP_INT_MAX, 2 );

		$response = wp_safe_remote_get(
			$url,
			array(
				'method'              => isset( $args['method'] ) ? $args['method'] : 'GET',
				'timeout'             => (int) $args['timeout'],
				'redirection'         => 0,
				'limit_response_size' => (int) $args['max_bytes'],
				'user-agent'          => (string) $args['user_agent'],
				'cookies'             => array(),
				'headers'             => array( 'Accept' => 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.5' ),
				'reject_unsafe_urls'  => true,
				'sslverify'           => true,
				'stream'              => false,
				'decompress'          => true,
			)
		);

		remove_action( 'http_api_curl', $pinner, PHP_INT_MAX );
		remove_filter( 'http_request_host_is_external', $external, PHP_INT_MAX );
		remove_filter( 'http_allowed_safe_ports', $ports, PHP_INT_MAX );
		$result['pinned'] = $applied;

		if ( is_wp_error( $response ) ) {
			$message              = $response->get_error_message();
			$result['error']      = $message;
			$result['error_code'] = preg_match( '/timed? ?out|Operation timed out|cURL error 28/i', $message ) ? 'timeout' : 'transport_error';
			return $result;
		}

		if ( ! $applied ) {
			// Another transport answered, so the address was not pinned. Discard it.
			$result['error']      = 'The request was not made through a pinned connection.';
			$result['error_code'] = 'pin_not_applied';
			return $result;
		}

		$headers = array();
		$raw     = wp_remote_retrieve_headers( $response );
		// Casting the Requests header dictionary to an array yields its
		// private storage, not the headers, so read it through getAll().
		$raw = is_object( $raw ) && method_exists( $raw, 'getAll' ) ? $raw->getAll() : (array) $raw;
		foreach ( $raw as $name => $value ) {
			$headers[ strtolower( (string) $name ) ] = is_array( $value ) ? implode( ', ', $value ) : (string) $value;
		}
		$body = (string) wp_remote_retrieve_body( $response );

		$result['status']    = (int) wp_remote_retrieve_response_code( $response );
		$result['headers']   = $headers;
		$result['body']      = $body;
		$result['truncated'] = strlen( $body ) >= (int) $args['max_bytes']
			|| ( isset( $headers['content-length'] ) && (int) $headers['content-length'] > (int) $args['max_bytes'] );
		return $result;
	}

	/**
	 * The host, when it is the www or bare variant of a home host that may
	 * be private and the connection is pinned to a loopback or private
	 * address; otherwise ''.
	 *
	 * @param string $host      Requested host.
	 * @param string $pinned_ip Address the connection will use.
	 * @return string
	 */
	private function private_variant( $host, $pinned_ip ) {
		if ( ! $this->allow_private_self ) {
			return '';
		}
		$class = UrlPolicy::classify_ip( $pinned_ip );
		if ( 'loopback' !== $class && 'private' !== $class ) {
			return '';
		}
		$home   = (string) get_option( 'home' );
		$policy = new UrlPolicy( $home, true );
		$host   = strtolower( (string) $host );
		if ( $host === $policy->home_host() || ! $policy->is_own_host( $host ) ) {
			return '';
		}
		return $host;
	}
}
