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
}
