<?php
/**
 * Which URLs and addresses the audit may request.
 *
 * Threat model F1, F2, F6: only the site's own host (and its www/bare
 * variant), only ports 80, 443 or the home URL's own port, never admin,
 * login, XML-RPC or REST routes, never a private, loopback, link-local or
 * metadata address. Query strings are dropped by default.
 *
 * @package MLT\SchemaAudit
 */

namespace MLT\SchemaAudit\Engine;

defined( 'ABSPATH' ) || defined( 'MLTSA_TESTING' ) || exit;

/**
 * URL and address policy.
 */
class UrlPolicy {

	/**
	 * Lower-case host of the site's home URL.
	 *
	 * @var string
	 */
	private $home_host;

	/**
	 * Scheme of the site's home URL.
	 *
	 * @var string
	 */
	private $home_scheme;

	/**
	 * Explicit port of the home URL, or 0.
	 *
	 * @var int
	 */
	private $home_port;

	/**
	 * Whether the site's own host may resolve to a loopback or private address.
	 *
	 * Off by default. Only for local development and staging boxes where the
	 * site name resolves to 127.0.0.1 or a LAN address; set with the
	 * MLTSA_ALLOW_PRIVATE_SELF constant. Never extends to other hosts, and
	 * never to link-local or cloud metadata addresses.
	 *
	 * @var bool
	 */
	private $allow_private_self;

	/**
	 * Resolver callable: host => array of IP strings.
	 *
	 * @var callable
	 */
	private $resolver;

	/**
	 * Paths that are never requested, whatever links to them.
	 *
	 * @var array
	 */
	private static $denied_paths = array(
		'#^/wp-admin(/|$)#i',
		'#^/wp-login\.php#i',
		'#^/xmlrpc\.php#i',
		'#^/wp-json(/|$)#i',
		'#^/wp-cron\.php#i',
		'#^/wp-content/#i',
		'#^/wp-includes/#i',
		'#/feed/?$#i',
		'#^/cart/?#i',
		'#^/checkout/?#i',
		'#^/my-account/?#i',
		'#/(logout|log-out|sign-out)/?#i',
	);

	/**
	 * Constructor.
	 *
	 * @param string        $home_url           Site home URL.
	 * @param bool          $allow_private_self Allow own host on private addresses.
	 * @param callable|null $resolver           Optional resolver for tests.
	 */
	public function __construct( $home_url, $allow_private_self = false, $resolver = null ) {
		$parts                    = parse_url( (string) $home_url ); // phpcs:ignore WordPress.WP.AlternativeFunctions.parse_url_parse_url -- Pure engine class, also runs outside WordPress in tests.
		$this->home_host          = isset( $parts['host'] ) ? strtolower( $parts['host'] ) : '';
		$this->home_scheme        = isset( $parts['scheme'] ) ? strtolower( $parts['scheme'] ) : 'https';
		$this->home_port          = isset( $parts['port'] ) ? (int) $parts['port'] : 0;
		$this->allow_private_self = (bool) $allow_private_self;
		$this->resolver           = is_callable( $resolver ) ? $resolver : array( __CLASS__, 'default_resolve' );
	}

	/**
	 * The site's own host.
	 *
	 * @return string
	 */
	public function home_host() {
		return $this->home_host;
	}

	/**
	 * The site's own scheme.
	 *
	 * @return string
	 */
	public function home_scheme() {
		return $this->home_scheme;
	}

	/**
	 * Hosts the audit may request: the home host and its www or bare variant.
	 *
	 * @return array
	 */
	public function allowed_hosts() {
		if ( '' === $this->home_host ) {
			return array();
		}
		$hosts = array( $this->home_host );
		if ( 0 === strpos( $this->home_host, 'www.' ) ) {
			$hosts[] = substr( $this->home_host, 4 );
		} elseif ( ! filter_var( $this->home_host, FILTER_VALIDATE_IP ) && false !== strpos( $this->home_host, '.' ) ) {
			$hosts[] = 'www.' . $this->home_host;
		}
		return $hosts;
	}

	/**
	 * Whether a host is the site's own.
	 *
	 * @param string $host Host.
	 * @return bool
	 */
	public function is_own_host( $host ) {
		return in_array( strtolower( (string) $host ), $this->allowed_hosts(), true );
	}

	/**
	 * Normalise a URL for the frozen list: absolute, no fragment, no query,
	 * lower-case scheme and host. Returns '' for anything unusable.
	 *
	 * @param string $url  URL, possibly relative.
	 * @param string $base Base URL for relative references.
	 * @return string
	 */
	public function normalise( $url, $base = '' ) {
		$url = trim( html_entity_decode( (string) $url, ENT_QUOTES | ENT_HTML5, 'UTF-8' ) );
		if ( '' === $url ) {
			return '';
		}
		if ( '' !== $base ) {
			$url = self::resolve_reference( $base, $url );
		}
		$parts = parse_url( $url ); // phpcs:ignore WordPress.WP.AlternativeFunctions.parse_url_parse_url
		if ( ! is_array( $parts ) || empty( $parts['scheme'] ) || empty( $parts['host'] ) ) {
			return '';
		}
		$scheme = strtolower( $parts['scheme'] );
		if ( 'http' !== $scheme && 'https' !== $scheme ) {
			return '';
		}
		$out = $scheme . '://' . strtolower( $parts['host'] );
		if ( isset( $parts['port'] ) ) {
			$out .= ':' . (int) $parts['port'];
		}
		$out .= isset( $parts['path'] ) && '' !== $parts['path'] ? self::remove_dot_segments( $parts['path'] ) : '/';
		return $out;
	}

	/**
	 * Check a URL against the request policy (not its address).
	 *
	 * @param string $url Absolute URL.
	 * @return array { ok: bool, reason: string }
	 */
	public function check_url( $url ) {
		$parts = parse_url( (string) $url ); // phpcs:ignore WordPress.WP.AlternativeFunctions.parse_url_parse_url
		if ( ! is_array( $parts ) || empty( $parts['scheme'] ) || empty( $parts['host'] ) ) {
			return self::verdict( false, 'invalid_url' );
		}
		$scheme = strtolower( $parts['scheme'] );
		if ( 'http' !== $scheme && 'https' !== $scheme ) {
			return self::verdict( false, 'scheme_not_allowed' );
		}
		if ( isset( $parts['user'] ) || isset( $parts['pass'] ) ) {
			return self::verdict( false, 'credentials_in_url' );
		}
		if ( ! $this->is_own_host( $parts['host'] ) ) {
			return self::verdict( false, 'off_site_host' );
		}
		if ( isset( $parts['port'] ) ) {
			$port = (int) $parts['port'];
			if ( 80 !== $port && 443 !== $port && $port !== $this->home_port ) {
				return self::verdict( false, 'port_not_allowed' );
			}
		}
		// The deny list is checked against the path as sent and as a server
		// would read it (decoded, dot segments and repeated slashes removed),
		// so /public/../wp-admin/ and /%2e%2e/wp-admin/ are refused too.
		$raw = isset( $parts['path'] ) ? $parts['path'] : '/';
		foreach ( array( rawurldecode( $raw ), self::canonical_path( $raw ) ) as $path ) {
			foreach ( self::$denied_paths as $pattern ) {
				if ( preg_match( $pattern, $path ) ) {
					return self::verdict( false, 'denied_path' );
				}
			}
		}
		if ( isset( $parts['query'] ) && preg_match( '/(^|&)(rest_route|action|_wpnonce|add-to-cart|logout)=/i', $parts['query'] ) ) {
			return self::verdict( false, 'denied_query' );
		}
		return self::verdict( true, '' );
	}

	/**
	 * Resolve a host and check every address it resolves to.
	 *
	 * All addresses must pass, so a round-robin record cannot slip a private
	 * address in. The first address is returned for connection pinning (F2).
	 *
	 * @param string $host Host.
	 * @return array { ok: bool, reason: string, ip: string, class: string }
	 */
	public function check_host_addresses( $host ) {
		$host = strtolower( trim( (string) $host, '[]' ) );
		$ips  = filter_var( $host, FILTER_VALIDATE_IP ) ? array( $host ) : (array) call_user_func( $this->resolver, $host );
		$ips  = array_values( array_filter( array_map( 'strval', $ips ) ) );
		if ( empty( $ips ) ) {
			return array(
				'ok'     => false,
				'reason' => 'dns_failure',
				'ip'     => '',
				'class'  => '',
			);
		}
		foreach ( $ips as $ip ) {
			$class = self::classify_ip( $ip );
			if ( ! $this->address_allowed( $host, $class ) ) {
				return array(
					'ok'     => false,
					'reason' => 'address_' . $class,
					'ip'     => $ip,
					'class'  => $class,
				);
			}
		}
		return array(
			'ok'     => true,
			'reason' => '',
			'ip'     => $ips[0],
			'class'  => self::classify_ip( $ips[0] ),
		);
	}

	/**
	 * Whether an address class is allowed for a host.
	 *
	 * @param string $host  Host.
	 * @param string $address_class Address class from classify_ip().
	 * @return bool
	 */
	private function address_allowed( $host, $address_class ) {
		if ( 'public' === $address_class ) {
			return true;
		}
		if ( $this->allow_private_self && $this->is_own_host( $host ) && ( 'loopback' === $address_class || 'private' === $address_class ) ) {
			return true;
		}
		return false;
	}

	/**
	 * Classify an IP address.
	 *
	 * Addresses are judged by their bytes, never their spelling, so ::1,
	 * 0:0:0:0:0:0:0:1 and ::ffff:7f00:1 are all loopback. IPv6 forms that
	 * carry an IPv4 address (mapped, NAT64, 6to4) are judged as that address.
	 *
	 * @param string $ip IPv4 or IPv6 address.
	 * @return string public|private|loopback|link_local|metadata|reserved|invalid
	 */
	public static function classify_ip( $ip ) {
		$ip = strtolower( trim( (string) $ip, '[] ' ) );
		if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return 'invalid';
		}
		$bin = inet_pton( $ip );
		if ( false === $bin ) {
			return 'invalid';
		}
		if ( 4 === strlen( $bin ) ) {
			return self::classify_ipv4( $bin );
		}
		$zeros = str_repeat( "\0", 10 );
		if ( $zeros . "\xff\xff" === substr( $bin, 0, 12 ) ) {
			return self::classify_ipv4( substr( $bin, 12 ) ); // ::ffff:0:0/96, IPv4-mapped.
		}
		if ( "\x00\x64\xff\x9b" . str_repeat( "\0", 8 ) === substr( $bin, 0, 12 ) ) {
			return self::classify_ipv4( substr( $bin, 12 ) ); // 64:ff9b::/96, NAT64.
		}
		if ( "\x20\x02" === substr( $bin, 0, 2 ) ) {
			return self::classify_ipv4( substr( $bin, 2, 4 ) ); // 2002::/16, 6to4.
		}
		if ( str_repeat( "\0", 15 ) . "\x01" === $bin ) {
			return 'loopback';
		}
		if ( str_repeat( "\0", 8 ) === substr( $bin, 0, 8 ) ) {
			// ::, IPv4-compatible ::/96 and IPv4-translated ::ffff:0:0:0/96.
			return 'reserved';
		}
		if ( inet_pton( 'fd00:ec2::254' ) === $bin ) {
			return 'metadata';
		}
		$first  = ord( $bin[0] );
		$second = ord( $bin[1] );
		if ( 0xfe === $first && 0x80 === ( $second & 0xc0 ) ) {
			return 'link_local';
		}
		if ( 0xfc === ( $first & 0xfe ) || ( 0xfe === $first && 0xc0 === ( $second & 0xc0 ) ) ) {
			return 'private'; // fc00::/7 unique local, fec0::/10 old site-local.
		}
		if ( 0xff === $first ) {
			return 'reserved';
		}
		if ( 0x20 === $first && 0x01 === $second && ( ( 0x0d === ord( $bin[2] ) && 0xb8 === ord( $bin[3] ) ) || "\0\0" === substr( $bin, 2, 2 ) ) ) {
			return 'reserved'; // 2001:db8::/32 documentation, 2001::/32 Teredo.
		}
		if ( "\x00\x64\xff\x9b\x00\x01" === substr( $bin, 0, 6 ) ) {
			return 'reserved'; // 64:ff9b:1::/48, local-use NAT64.
		}
		return 'public';
	}

	/**
	 * Classify a packed IPv4 address.
	 *
	 * @param string $bin Four bytes.
	 * @return string
	 */
	private static function classify_ipv4( $bin ) {
		$ip   = inet_ntop( $bin );
		$long = ip2long( $ip );
		$in   = static function ( $cidr ) use ( $long ) {
			list( $net, $bits ) = explode( '/', $cidr );
			$mask               = -1 << ( 32 - (int) $bits );
			return ( $long & $mask ) === ( ip2long( $net ) & $mask );
		};
		if ( '169.254.169.254' === $ip || '100.100.100.200' === $ip ) {
			return 'metadata';
		}
		if ( $in( '127.0.0.0/8' ) ) {
			return 'loopback';
		}
		if ( $in( '169.254.0.0/16' ) ) {
			return 'link_local';
		}
		if ( $in( '10.0.0.0/8' ) || $in( '172.16.0.0/12' ) || $in( '192.168.0.0/16' ) || $in( '100.64.0.0/10' ) ) {
			return 'private';
		}
		if ( $in( '0.0.0.0/8' ) || $in( '192.0.0.0/24' ) || $in( '192.0.2.0/24' ) || $in( '198.18.0.0/15' ) || $in( '198.51.100.0/24' ) || $in( '203.0.113.0/24' ) || $in( '224.0.0.0/4' ) || $in( '240.0.0.0/4' ) ) {
			return 'reserved';
		}
		return 'public';
	}

	/**
	 * Default resolver: IPv4 and IPv6 records. Never follows anything else.
	 *
	 * @param string $host Host.
	 * @return array
	 */
	public static function default_resolve( $host ) {
		$ips = array();
		$v4  = gethostbynamel( $host );
		if ( is_array( $v4 ) ) {
			$ips = $v4;
		}
		if ( function_exists( 'dns_get_record' ) ) {
			$v6 = @dns_get_record( $host, DNS_AAAA ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Lookup failure is an expected outcome.
			if ( is_array( $v6 ) ) {
				foreach ( $v6 as $record ) {
					if ( ! empty( $record['ipv6'] ) ) {
						$ips[] = $record['ipv6'];
					}
				}
			}
		}
		return array_values( array_unique( $ips ) );
	}

	/**
	 * Resolve a reference against a base URL (RFC 3986, simplified).
	 *
	 * @param string $base Base URL.
	 * @param string $ref  Reference.
	 * @return string
	 */
	public static function resolve_reference( $base, $ref ) {
		$ref = trim( (string) $ref );
		if ( preg_match( '#^[a-z][a-z0-9+.\-]*:#i', $ref ) ) {
			return $ref;
		}
		$b = parse_url( (string) $base ); // phpcs:ignore WordPress.WP.AlternativeFunctions.parse_url_parse_url
		if ( ! is_array( $b ) || empty( $b['scheme'] ) || empty( $b['host'] ) ) {
			return $ref;
		}
		$origin = $b['scheme'] . '://' . $b['host'] . ( isset( $b['port'] ) ? ':' . $b['port'] : '' );
		if ( 0 === strpos( $ref, '//' ) ) {
			return $b['scheme'] . ':' . $ref;
		}
		$base_path = isset( $b['path'] ) ? $b['path'] : '/';
		if ( '' === $ref ) {
			return $origin . $base_path . ( isset( $b['query'] ) ? '?' . $b['query'] : '' );
		}
		if ( '#' === $ref[0] ) {
			return $origin . $base_path . ( isset( $b['query'] ) ? '?' . $b['query'] : '' ) . $ref;
		}
		if ( '?' === $ref[0] ) {
			return $origin . $base_path . $ref;
		}
		if ( '/' === $ref[0] ) {
			$path = $ref;
		} else {
			$dir  = substr( $base_path, 0, (int) strrpos( $base_path, '/' ) + 1 );
			$path = $dir . $ref;
		}
		$suffix = '';
		if ( preg_match( '/^([^?#]*)([?#].*)$/', $path, $m ) ) {
			$path   = $m[1];
			$suffix = $m[2];
		}
		return $origin . self::remove_dot_segments( $path ) . $suffix;
	}

	/**
	 * Remove . and .. segments from a path (RFC 3986 section 5.2.4).
	 *
	 * @param string $path Path.
	 * @return string Path starting with a slash.
	 */
	public static function remove_dot_segments( $path ) {
		$segments = explode( '/', (string) $path );
		$out      = array();
		$last     = count( $segments ) - 1;
		foreach ( $segments as $i => $seg ) {
			if ( '..' === $seg ) {
				if ( count( $out ) > 1 ) {
					array_pop( $out );
				}
			} elseif ( '.' !== $seg ) {
				$out[] = $seg;
				continue;
			}
			if ( $i === $last ) {
				$out[] = ''; // A trailing dot segment leaves a directory: /a/b/.. is /a/.
			}
		}
		$path = implode( '/', $out );
		if ( '' === $path || '/' !== $path[0] ) {
			$path = '/' . $path;
		}
		return $path;
	}

	/**
	 * A path as a web server would read it, for policy checks only: percent
	 * decoding repeated until stable, backslashes as slashes, repeated
	 * slashes collapsed, dot segments removed.
	 *
	 * @param string $path Raw path.
	 * @return string
	 */
	public static function canonical_path( $path ) {
		$path = (string) $path;
		for ( $i = 0; $i < 3; $i++ ) {
			$decoded = rawurldecode( $path );
			if ( $decoded === $path ) {
				break;
			}
			$path = $decoded;
		}
		$path = str_replace( '\\', '/', $path );
		$path = (string) preg_replace( '#/{2,}#', '/', $path );
		return self::remove_dot_segments( $path );
	}

	/**
	 * Build a verdict array.
	 *
	 * @param bool   $ok     Allowed.
	 * @param string $reason Reason code when refused.
	 * @return array
	 */
	private static function verdict( $ok, $reason ) {
		return array(
			'ok'     => $ok,
			'reason' => $reason,
		);
	}
}
