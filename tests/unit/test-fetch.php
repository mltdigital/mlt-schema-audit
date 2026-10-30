<?php
/**
 * Threat model F1 to F7: fetch policy and safe fetching.
 *
 * @package MLT\SchemaAudit
 */

// phpcs:disable

use MLT\SchemaAudit\Engine\Fetcher;
use MLT\SchemaAudit\Engine\UrlPolicy;

function mltsa_policy( $allow_private = false, $map = array() ) {
	$map = array_merge(
		array(
			'www.example-legal.co.uk' => array( '203.0.114.10' ),
			'example-legal.co.uk'     => array( '203.0.114.10' ),
		),
		$map
	);
	return new UrlPolicy(
		'https://www.example-legal.co.uk',
		$allow_private,
		static function ( $host ) use ( $map ) {
			return isset( $map[ $host ] ) ? $map[ $host ] : array();
		}
	);
}

function mltsa_fetcher( Scripted_Client $client, $policy = null ) {
	return new Fetcher( $policy ? $policy : mltsa_policy(), $client, array( 'user_agent' => 'MLT-Schema-Audit/test' ), static function () {} );
}

mltsa_test(
	'F1 redirects to internal addresses and off-site hosts are refused and logged as blocked',
	static function () {
		$targets = array(
			'http://127.0.0.1/'                 => 'off_site_host',
			'http://10.0.0.5/admin'             => 'off_site_host',
			'http://169.254.169.254/latest/meta-data/' => 'off_site_host',
			'http://[::1]/'                     => 'off_site_host',
			'https://evil.example.net/'         => 'off_site_host',
			'https://www.example-legal.co.uk:8080/' => 'port_not_allowed',
		);
		foreach ( $targets as $target => $reason ) {
			$client = new Scripted_Client();
			$client->responses['https://www.example-legal.co.uk/start/'] = array( 'status' => 302, 'headers' => array( 'location' => $target ) );
			$result = mltsa_fetcher( $client )->fetch( 'https://www.example-legal.co.uk/start/' );
			check_same( 'blocked', $result['outcome'], 'redirect to ' . $target );
			check_same( $reason, $result['reason'], 'reason for ' . $target );
			check_same( 1, count( $client->requests ), 'no request made to ' . $target );
		}
	}
);

mltsa_test(
	'F1 own host resolving to a private, loopback, link-local or metadata address is refused',
	static function () {
		foreach ( array( '127.0.0.1' => 'loopback', '10.1.2.3' => 'private', '172.20.0.1' => 'private', '192.168.1.1' => 'private', '169.254.169.254' => 'metadata', '169.254.10.10' => 'link_local', '::1' => 'loopback', 'fe80::1' => 'link_local', 'fd00::1' => 'private', '::ffff:127.0.0.1' => 'loopback', '0.0.0.0' => 'reserved' ) as $ip => $class ) {
			check_same( $class, UrlPolicy::classify_ip( $ip ), 'classify ' . $ip );
			$client = new Scripted_Client();
			$result = mltsa_fetcher( $client, mltsa_policy( false, array( 'www.example-legal.co.uk' => array( $ip ) ) ) )->fetch( 'https://www.example-legal.co.uk/' );
			check_same( 'blocked', $result['outcome'], 'own host on ' . $ip );
			check_same( 0, count( $client->requests ), 'no request for ' . $ip );
		}
		// Round-robin with one bad address is refused as a whole.
		$client = new Scripted_Client();
		$result = mltsa_fetcher( $client, mltsa_policy( false, array( 'www.example-legal.co.uk' => array( '203.0.114.10', '10.0.0.1' ) ) ) )->fetch( 'https://www.example-legal.co.uk/' );
		check_same( 'blocked', $result['outcome'], 'mixed record set' );
	}
);

mltsa_test(
	'F1 development allowance covers only the site\'s own host on loopback or private, never metadata',
	static function () {
		$policy = mltsa_policy( true, array( 'www.example-legal.co.uk' => array( '127.0.0.1' ) ) );
		check( $policy->check_host_addresses( 'www.example-legal.co.uk' )['ok'], 'own host on loopback allowed in dev' );
		$policy = mltsa_policy( true, array( 'www.example-legal.co.uk' => array( '169.254.169.254' ) ) );
		check( ! $policy->check_host_addresses( 'www.example-legal.co.uk' )['ok'], 'metadata never allowed' );
		$policy = mltsa_policy( true, array( 'other.example.net' => array( '127.0.0.1' ) ) );
		check( ! $policy->check_host_addresses( 'other.example.net' )['ok'], 'other host on loopback refused' );
	}
);

mltsa_test(
	'F2 the connection is pinned to the address that was checked',
	static function () {
		$client = new Scripted_Client();
		$client->responses['https://www.example-legal.co.uk/'] = array( 'status' => 200, 'body' => '<html></html>' );
		mltsa_fetcher( $client )->fetch( 'https://www.example-legal.co.uk/' );
		check_same( '203.0.114.10', $client->requests[0]['ip'], 'pinned address' );
		// A redirect to the bare host is re-resolved and re-checked.
		$client = new Scripted_Client();
		$client->responses['https://www.example-legal.co.uk/a/'] = array( 'status' => 301, 'headers' => array( 'location' => 'https://example-legal.co.uk/a/' ) );
		$client->responses['https://example-legal.co.uk/a/']     = array( 'status' => 200, 'body' => 'x' );
		$result = mltsa_fetcher( $client, mltsa_policy( false, array( 'example-legal.co.uk' => array( '203.0.114.99' ) ) ) )->fetch( 'https://www.example-legal.co.uk/a/' );
		check_same( 'ok', $result['outcome'], 'bare host redirect followed' );
		check_same( '203.0.114.99', $client->requests[1]['ip'], 'second hop pinned to its own checked address' );
		check_same( 2, count( $result['chain'] ), 'redirect chain recorded' );
	}
);

mltsa_test(
	'F2 a response not made through a pinned connection is discarded',
	static function () {
		$client = new Scripted_Client();
		$client->responses['https://www.example-legal.co.uk/'] = array( 'error_code' => 'pin_not_applied', 'status' => 0 );
		$result = mltsa_fetcher( $client )->fetch( 'https://www.example-legal.co.uk/' );
		check_same( 'error', $result['outcome'], 'unpinned response refused' );
		check_same( '', $result['body'], 'no body kept' );
	}
);

mltsa_test(
	'F3 oversized and timed-out responses are recorded and not parsed; timeouts are not retried',
	static function () {
		$client = new Scripted_Client();
		$client->responses['https://www.example-legal.co.uk/big/']  = array( 'status' => 200, 'body' => str_repeat( 'a', 100 ), 'truncated' => true );
		$client->responses['https://www.example-legal.co.uk/slow/'] = array( 'status' => 0, 'error_code' => 'timeout' );
		$fetcher = mltsa_fetcher( $client );
		$big     = $fetcher->fetch( 'https://www.example-legal.co.uk/big/' );
		check_same( 'too_large', $big['outcome'], 'too large' );
		check_same( '', $big['body'], 'oversized body dropped' );
		$slow = $fetcher->fetch( 'https://www.example-legal.co.uk/slow/' );
		check_same( 'timeout', $slow['outcome'], 'timeout' );
		check_same( 1, $slow['attempts'], 'timeout not retried' );
	}
);

mltsa_test(
	'F3 transient failures retry with backoff, at most twice',
	static function () {
		$client = new Scripted_Client();
		$client->responses['https://www.example-legal.co.uk/busy/'] = array( 'status' => 503 );
		$sleeps  = array();
		$fetcher = new Fetcher( mltsa_policy(), $client, array(), static function ( $s ) use ( &$sleeps ) { $sleeps[] = $s; } );
		$result  = $fetcher->fetch( 'https://www.example-legal.co.uk/busy/' );
		check_same( 3, $result['attempts'], 'one try plus two retries' );
		check_same( array( 2, 4 ), $sleeps, 'backoff' );
		check_same( 'http_error', $result['outcome'], 'recorded as http error' );
	}
);

mltsa_test(
	'F3 redirect loops stop at the hop limit',
	static function () {
		$client = new Scripted_Client();
		$client->responses['https://www.example-legal.co.uk/a/'] = array( 'status' => 302, 'headers' => array( 'location' => '/b/' ) );
		$client->responses['https://www.example-legal.co.uk/b/'] = array( 'status' => 302, 'headers' => array( 'location' => '/a/' ) );
		$result = mltsa_fetcher( $client )->fetch( 'https://www.example-legal.co.uk/a/' );
		check_same( 'redirect_limit', $result['outcome'], 'loop stopped' );
		check_same( 6, count( $client->requests ), 'first request plus five hops' );
	}
);

mltsa_test(
	'F6 admin, login, XML-RPC, REST and side-effect URLs are never requested',
	static function () {
		$policy = mltsa_policy();
		foreach ( array( '/wp-admin/', '/wp-admin/admin-ajax.php', '/wp-login.php?action=logout', '/xmlrpc.php', '/wp-json/wp/v2/users', '/?rest_route=/wp/v2/users', '/cart/?add-to-cart=12', '/wp-cron.php', '/my-account/customer-logout/' ) as $path ) {
			check( ! $policy->check_url( 'https://www.example-legal.co.uk' . $path )['ok'], 'refused ' . $path );
		}
		check( $policy->check_url( 'https://www.example-legal.co.uk/services/conveyancing/' )['ok'], 'ordinary page allowed' );
		check_same( 'https://www.example-legal.co.uk/a/', $policy->normalise( 'https://WWW.example-legal.co.uk/a/?utm_source=x#top' ), 'query and fragment dropped' );
		check_same( '', $policy->normalise( 'javascript:alert(1)' ), 'javascript scheme dropped' );
		check_same( '', $policy->normalise( 'mailto:x@example.net' ), 'mailto dropped' );
	}
);

mltsa_test(
	'F7 requests carry no cookies or authorisation, and 401 is unavailable, never retried with credentials',
	static function () {
		$client = new Scripted_Client();
		$client->responses['https://www.example-legal.co.uk/'] = array( 'status' => 401 );
		$result = mltsa_fetcher( $client )->fetch( 'https://www.example-legal.co.uk/' );
		check_same( 'unavailable', $result['outcome'], 'basic auth recorded as unavailable' );
		check_same( 1, count( $client->requests ), 'no second attempt' );
		$args = $client->requests[0]['args'];
		check( ! isset( $args['cookies'] ) && ! isset( $args['headers'] ), 'no cookie or header arguments passed to the transport' );
		check( 0 === strpos( $args['user_agent'], 'MLT-Schema-Audit/' ), 'identifiable user agent (F8)' );
		// The WordPress transport passes an empty cookie jar and only an Accept header.
		$source = file_get_contents( MLTSA_DIR . 'includes/Engine/WpHttpClient.php' );
		check( false !== strpos( $source, "'cookies'             => array()" ), 'empty cookie jar in WP transport' );
		check( false === stripos( $source, 'Authorization' ), 'no Authorization header in WP transport' );
		check( false !== strpos( $source, "'redirection'         => 0" ), 'redirects off in WP transport' );
		check( false !== strpos( $source, 'CURLOPT_RESOLVE' ), 'pinning via CURLOPT_RESOLVE' );
	}
);

mltsa_test(
	'F1 credentials in URLs and non-web schemes are refused',
	static function () {
		$policy = mltsa_policy();
		check( ! $policy->check_url( 'https://user:pass@www.example-legal.co.uk/' )['ok'], 'userinfo refused' );
		check( ! $policy->check_url( 'ftp://www.example-legal.co.uk/' )['ok'], 'ftp refused' );
		check( ! $policy->check_url( 'file:///etc/passwd' )['ok'], 'file refused' );
		check( ! $policy->check_url( 'gopher://www.example-legal.co.uk/' )['ok'], 'gopher refused' );
	}
);
