<?php
/**
 * Threat model F1 to F7: fetch policy and safe fetching.
 *
 * @package MLT\SchemaAudit
 */

// phpcs:disable

use MLT\SchemaAudit\Discovery;
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

mltsa_test(
	'F1 review 2026-10-30: IPv6 spellings of private addresses are judged by their bytes',
	static function () {
		$cases = array(
			'::ffff:7f00:1'           => 'loopback',
			'::ffff:a00:1'            => 'private',
			'::ffff:a9fe:a9fe'        => 'metadata',
			'0:0:0:0:0:0:0:1'         => 'loopback',
			'0000::0001'              => 'loopback',
			'0:0:0:0:0:ffff:7f00:1'   => 'loopback',
			'64:ff9b::7f00:1'         => 'loopback',
			'2002:c0a8:0101::1'       => 'private',
			'::7f00:1'                => 'reserved',
			'::'                      => 'reserved',
			'fd00:ec2:0:0:0:0:0:254'  => 'metadata',
			'fec0::1'                 => 'private',
			'2001:0:4136:e378::1'     => 'reserved',
			'2a00:1450:4009:81f::200e' => 'public',
			'::ffff:203.0.114.10'     => 'public',
		);
		foreach ( $cases as $ip => $class ) {
			check_same( $class, UrlPolicy::classify_ip( $ip ), 'classify ' . $ip );
		}
		$policy = mltsa_policy( false, array( 'www.example-legal.co.uk' => array( '::ffff:7f00:1' ) ) );
		$check  = $policy->check_host_addresses( 'www.example-legal.co.uk' );
		check_same( false, $check['ok'], 'mapped loopback refused without the private-self allowance' );
	}
);

mltsa_test(
	'F1 review 2026-10-30: dot segments, encoded dots and doubled slashes cannot reach denied paths',
	static function () {
		$policy = mltsa_policy();
		foreach ( array( '/public/../wp-admin/', '/./wp-admin/', '/page/../wp-login.php', '/%2e%2e/wp-admin/', '/a/%2E%2E/xmlrpc.php', '//wp-admin/', '/x/..%2fwp-json/', '/a%5c..%5cwp-admin/', '/%252e%252e/wp-admin/' ) as $path ) {
			$check = $policy->check_url( 'https://www.example-legal.co.uk' . $path );
			check_same( 'denied_path', $check['reason'], 'denied ' . $path );
		}
		check_same( true, $policy->check_url( 'https://www.example-legal.co.uk/services/../about/' )['ok'], 'harmless traversal still allowed' );
		check_same( 'https://www.example-legal.co.uk/about/', $policy->normalise( 'https://www.example-legal.co.uk/services/../about/' ), 'normalise removes dot segments' );
		check_same( '/a/', UrlPolicy::remove_dot_segments( '/a/b/..' ), 'trailing dot segment leaves a directory' );
		$client = new Scripted_Client();
		$client->responses['https://www.example-legal.co.uk/start/'] = array( 'status' => 302, 'headers' => array( 'location' => 'https://www.example-legal.co.uk/x/../wp-admin/' ) );
		$result = mltsa_fetcher( $client )->fetch( 'https://www.example-legal.co.uk/start/' );
		check_same( 'blocked', $result['outcome'], 'absolute redirect with traversal refused' );
		check_same( 1, count( $client->requests ), 'no request made to the traversal target' );
	}
);

mltsa_test(
	'F6 review 2026-10-30: image checks may request static files under wp-content, never scripts, and pages never',
	static function () {
		$policy = mltsa_policy();
		$base   = 'https://www.example-legal.co.uk';
		foreach ( array( '/wp-content/uploads/2026/03/logo.png', '/wp-content/uploads/team.JPG', '/wp-content/themes/firm/img/logo.svg', '/wp-includes/images/w-logo-blue.png', '/wp-content/uploads/brochure.pdf', '/wp-content/uploads/logo.webp?ver=2' ) as $path ) {
			check_same( true, $policy->check_url( $base . $path, true )['ok'], 'resource allowed ' . $path );
			check_same( 'denied_path', $policy->check_url( $base . $path )['reason'], 'page fetch still refused ' . $path );
		}
		foreach ( array( '/wp-content/plugins/x/run.php', '/wp-content/plugins/x/run.php/a.png', '/wp-content/uploads/a.php.png', '/wp-content/uploads/a.phtml', '/wp-content/uploads/a.php%00.png', '/wp-content/uploads/', '/wp-content/uploads/a.png/..', '/wp-content/uploads/../plugins/x/run.php', '/wp-content/uploads/a%2ephp%2fb.png', '/wp-includes/ms-files.php', '/wp-admin/images/logo.png', '/wp-json/wp/v2/media.png' ) as $path ) {
			check_same( 'denied_path', $policy->check_url( $base . $path, true )['reason'], 'resource refused ' . $path );
		}
		check_same( 'denied_query', $policy->check_url( $base . '/wp-content/uploads/a.png?action=delete', true )['reason'], 'side-effect query refused on a resource' );
		check_same( 'off_site_host', $policy->check_url( 'https://cdn.example.net/wp-content/uploads/a.png', true )['reason'], 'other hosts still refused' );

		$client = new Scripted_Client();
		$client->responses[ $base . '/wp-content/uploads/logo.png' ] = array( 'status' => 200 );
		$result = mltsa_fetcher( $client )->fetch( $base . '/wp-content/uploads/logo.png', 'HEAD', true );
		check_same( 'ok', $result['outcome'], 'upload checked' );

		$client = new Scripted_Client();
		$client->responses[ $base . '/wp-content/uploads/old.png' ] = array( 'status' => 301, 'headers' => array( 'location' => $base . '/wp-content/plugins/x/run.php' ) );
		$result = mltsa_fetcher( $client )->fetch( $base . '/wp-content/uploads/old.png', 'HEAD', true );
		check_same( 'blocked', $result['outcome'], 'redirect from an image to a script refused' );
		check_same( 1, count( $client->requests ), 'no request made to the script' );
	}
);

mltsa_test(
	'Branch review R1: a request starts only with the full timeout left, is never cut short, and a timeout is the site\'s',
	static function () {
		$client = new Scripted_Client();
		$client->responses['https://www.example-legal.co.uk/slow/'] = array( 'status' => 0, 'error_code' => 'timeout' );
		$fetcher = mltsa_fetcher( $client );

		$short = $fetcher->fetch( 'https://www.example-legal.co.uk/slow/', 'GET', false, microtime( true ) + 8 );
		check_same( 'deferred', $short['outcome'], 'less time left than the timeout: deferred' );
		check_same( 'budget_spent', $short['reason'], 'reason' );
		check_same( 0, $short['attempts'], 'no attempt counted' );
		check_same( 0, count( $client->requests ), 'no request made with less than the full timeout left' );

		$full = $fetcher->fetch( 'https://www.example-legal.co.uk/slow/', 'GET', false, microtime( true ) + 17 );
		check_same( 15, $client->requests[0]['args']['timeout'], 'the full setting is sent' );
		check_same( 'timeout', $full['outcome'], 'a timeout after the full setting is a timeout' );
		check_same( 1, $full['attempts'], 'one request made' );

		$client->responses['https://www.example-legal.co.uk/ten-seconds/'] = array( 'body' => '<html></html>' );
		for ( $i = 0; $i < 3; $i++ ) {
			$fetcher->fetch( 'https://www.example-legal.co.uk/ten-seconds/', 'GET', false, microtime( true ) + 8 );
		}
		$read = $fetcher->fetch( 'https://www.example-legal.co.uk/ten-seconds/', 'GET', false, microtime( true ) + 17 );
		check_same( 'ok', $read['outcome'], 'a page answering within the timeout is read once a slice has room' );
		foreach ( $client->requests as $request ) {
			check_same( 15, $request['args']['timeout'], 'no request is ever sent a shortened timeout' );
		}
	}
);

mltsa_test(
	'F4 review 2026-10-30: a retry that would run past the deadline is deferred instead of slept for',
	static function () {
		$client = new Scripted_Client();
		$client->responses['https://www.example-legal.co.uk/busy/'] = array( 'status' => 503 );
		$sleeps  = array();
		$fetcher = new Fetcher( mltsa_policy(), $client, array( 'timeout' => 3 ), static function ( $s ) use ( &$sleeps ) { $sleeps[] = $s; } );
		$result  = $fetcher->fetch( 'https://www.example-legal.co.uk/busy/', 'GET', false, microtime( true ) + 6.5 );
		check_same( array( 2 ), $sleeps, 'first backoff and a full timeout fit, second does not' );
		check_same( 2, $result['attempts'], 'two requests' );
		check_same( 'deferred', $result['outcome'], 'deferred' );
		check_same( 'budget_retry', $result['reason'], 'reason' );
	}
);

mltsa_test(
	'Branch review R1: sitemap discovery reads a slow sitemap, counts only fair deferrals, and records sitemaps it could not read',
	static function () {
		$client = new Scripted_Client();
		$client->responses['https://www.example-legal.co.uk/wp-sitemap.xml'] = array( 'body' => '<sitemapindex><sitemap><loc>https://www.example-legal.co.uk/wp-sitemap-posts-page-1.xml</loc></sitemap><sitemap><loc>https://www.example-legal.co.uk/wp-sitemap-posts-post-1.xml</loc></sitemap></sitemapindex>', 'headers' => array( 'content-type' => 'application/xml' ) );
		$client->responses['https://www.example-legal.co.uk/wp-sitemap-posts-page-1.xml'] = array( 'status' => 503 );
		$client->responses['https://www.example-legal.co.uk/wp-sitemap-posts-post-1.xml'] = array( 'body' => '<urlset><url><loc>https://www.example-legal.co.uk/news/a/</loc></url></urlset>', 'headers' => array( 'content-type' => 'application/xml' ) );
		$policy  = mltsa_policy();
		$fetcher = new Fetcher( $policy, $client, array( 'timeout' => 3 ), static function () {} );
		$state   = Discovery::sitemap_state( $policy );

		$state = Discovery::sitemap_step( $fetcher, $policy, $state, microtime( true ) + 100 );
		check_same( 1, count( $client->requests ), 'one request for the index' );
		check_same( 2, count( $state['queue'] ), 'children queued, fallbacks dropped' );

		$state = Discovery::sitemap_step( $fetcher, $policy, $state, microtime( true ) + 2 );
		check( $state['deferred'], 'no room for the full timeout: deferred' );
		check_same( 1, count( $client->requests ), 'no request made' );
		check_same( 0, $state['deferrals'], 'not counted' );

		$state = Discovery::sitemap_step( $fetcher, $policy, $state, microtime( true ) + 4, false );
		check( $state['deferred'], 'retry did not fit: deferred' );
		check_same( 0, $state['deferrals'], 'a step without the whole slice does not count' );

		for ( $i = 1; $i <= 3; $i++ ) {
			$state = Discovery::sitemap_step( $fetcher, $policy, $state, microtime( true ) + 4, true );
			check_same( $i < 3, $state['deferred'], 'deferred until the third fair deferral, step ' . $i );
		}
		check_same( 2, $state['read'], 'third fair deferral counts the sitemap as read' );
		check_same( 1, $state['not_read'], 'and as not read' );
		check_same( array( 'https://www.example-legal.co.uk/wp-sitemap-posts-post-1.xml' ), $state['queue'], 'moved on to the next sitemap' );

		$state = Discovery::sitemap_step( $fetcher, $policy, $state, microtime( true ) + 100 );
		$state = Discovery::sitemap_step( $fetcher, $policy, $state, microtime( true ) + 100 );
		check( $state['done'], 'done once the queue is empty' );
		check_same( array( 'https://www.example-legal.co.uk/news/a/' ), array_column( $state['out'], 'url' ), 'URLs from the readable sitemap' );

		$client->responses['https://www.example-legal.co.uk/wp-sitemap-posts-page-1.xml'] = array( 'body' => '<urlset><url><loc>https://www.example-legal.co.uk/slow-a/</loc></url></urlset>', 'headers' => array( 'content-type' => 'application/xml' ) );
		$slow = new Fetcher( $policy, $client, array( 'timeout' => 15 ), static function () {} );
		$fresh = Discovery::sitemap_state( $policy );
		for ( $i = 0; $i < 6; $i++ ) {
			$fresh = Discovery::sitemap_step( $slow, $policy, $fresh, microtime( true ) + 8 );
		}
		check_same( 0, $fresh['read'], 'a slice shorter than the timeout never gives a sitemap up' );
		while ( ! $fresh['done'] ) {
			$fresh = Discovery::sitemap_step( $slow, $policy, $fresh, microtime( true ) + 17 );
		}
		check( in_array( 'https://www.example-legal.co.uk/slow-a/', array_column( $fresh['out'], 'url' ), true ), 'read once a slice has room for the full timeout' );
		check_same( 0, $fresh['not_read'], 'nothing left unread' );

		$client->requests = array();
		check_same( array( 'https://www.example-legal.co.uk/slow-a/', 'https://www.example-legal.co.uk/news/a/' ), array_column( Discovery::from_sitemaps( $fetcher, $policy ), 'url' ), 'one-call discovery unchanged without a deadline' );
	}
);
