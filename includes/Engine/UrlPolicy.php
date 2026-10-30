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
		$out .= isset( $parts['path'] ) && '' !== $parts['path'] ? $parts['path'] : '/';
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
		$path = isset( $parts['path'] ) ? rawurldecode( $parts['path'] ) : '/';
		foreach ( self::$denied_paths as $pattern ) {
			if ( preg_match( $pattern, $path ) ) {
				return self::verdict( false, 'denied_path' );
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
	 * @param string $class Address class from classify_ip().
	 * @return bool
	 */
	private function address_allowed( $host, $class ) {
		if ( 'public' === $class ) {
			return true;
		}
		if ( $this->allow_private_self && $this->is_own_host( $host ) && ( 'loopback' === $class || 'private' === $class ) ) {
			return true;
		}
		return false;
	}

	/**
	 * Classify an IP address.
	 *
	 * @param string $ip IPv4 or IPv6 address.
	 * @return string public|private|loopback|link_local|metadata|reserved|invalid
	 */
	public static function classify_ip( $ip ) {
		$ip = strtolower( trim( (string) $ip, '[] ' ) );
		if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return 'invalid';
		}
		// IPv4-mapped IPv6 (::ffff:127.0.0.1) is judged as the IPv4 inside it.
		if ( preg_match( '/^::ffff:(\d+\.\d+\.\d+\.\d+)$/', $ip, $m ) ) {
			$ip = $m[1];
		}
		if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
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
		if ( '::1' === $ip ) {
			return 'loopback';
		}
		if ( '::' === $ip ) {
			return 'reserved';
		}
		if ( 'fd00:ec2::254' === $ip ) {
			return 'metadata';
		}
		$bin = inet_pton( $ip );
		if ( false === $bin ) {
			return 'invalid';
		}
		$first = ord( $bin[0] );
		$second = ord( $bin[1] );
		if ( 0xfe === $first && 0x80 === ( $second & 0xc0 ) ) {
			return 'link_local';
		}
		if ( 0xfc === ( $first & 0xfe ) ) {
			return 'private';
		}
		if ( 0xff === $first || ( 0x20 === $first && 0x01 === $second && 0x0d === ord( $bin[2] ) && 0xb8 === ord( $bin[3] ) ) ) {
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
		$out = array();
		foreach ( explode( '/', $path ) as $seg ) {
			if ( '..' === $seg ) {
				if ( count( $out ) > 1 ) {
					array_pop( $out );
				}
			} elseif ( '.' !== $seg ) {
				$out[] = $seg;
			}
		}
		$path = implode( '/', $out );
		if ( '' === $path || '/' !== $path[0] ) {
			$path = '/' . $path;
		}
		return $origin . $path . $suffix;
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
