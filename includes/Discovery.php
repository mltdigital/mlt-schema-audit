<?php
/**
 * Builds a run's frozen URL list (contract section 4).
 *
 * Sources: the homepage (always, explicitly), published posts of the chosen
 * public post types, and optionally same-host sitemaps with a cap. Drafts and
 * private content are never queried. Password-protected posts, denied paths
 * and anything over the URL cap are recorded as exclusions with a reason.
 * Query strings and fragments are dropped (F6).
 *
 * @package MLT\SchemaAudit
 */

namespace MLT\SchemaAudit;

use MLT\SchemaAudit\Engine\Evaluator;
use MLT\SchemaAudit\Engine\Fetcher;
use MLT\SchemaAudit\Engine\UrlPolicy;

defined( 'ABSPATH' ) || defined( 'MLTSA_TESTING' ) || exit;

/**
 * Discovery.
 */
class Discovery {

	/**
	 * Most sitemap documents read in one discovery.
	 */
	const MAX_SITEMAPS = 20;

	/**
	 * Most URLs taken from sitemaps.
	 */
	const MAX_SITEMAP_URLS = 2000;

	/**
	 * Gather candidates from WordPress.
	 *
	 * @param array $settings Settings.
	 * @return array List of { url, source, post_id, exclude }.
	 */
	public static function from_wordpress( array $settings ) {
		$out   = array(
			array(
				'url'     => home_url( '/' ),
				'source'  => 'home',
				'post_id' => (int) get_option( 'page_on_front' ),
				'exclude' => '',
			),
		);
		$types = array_values( array_intersect( (array) $settings['post_types'], array_keys( get_post_types( array( 'public' => true ) ) ) ) );
		$types = array_values( array_diff( $types, array( 'attachment' ) ) );
		if ( empty( $types ) ) {
			return $out;
		}
		$paged = 1;
		$limit = (int) $settings['max_urls'] + 1;
		$taken = 0;
		do {
			$ids = get_posts(
				array(
					'post_type'        => $types,
					'post_status'      => 'publish',
					'fields'           => 'ids',
					'posts_per_page'   => 200,
					'paged'            => $paged,
					'orderby'          => 'ID',
					'order'            => 'ASC',
					'no_found_rows'    => true,
					'suppress_filters' => true,
				)
			);
			foreach ( $ids as $id ) {
				$post = get_post( $id );
				if ( ! $post ) {
					continue;
				}
				$out[] = array(
					'url'     => (string) get_permalink( $post ),
					'source'  => 'post:' . $post->post_type,
					'post_id' => (int) $id,
					'exclude' => '' !== $post->post_password ? 'password_protected' : '',
				);
				++$taken;
			}
			++$paged;
		} while ( count( $ids ) === 200 && $taken < $limit );
		return $out;
	}

	/**
	 * Gather candidates from same-host sitemaps, with caps.
	 *
	 * @param Fetcher   $fetcher Fetcher (same policy as page fetches).
	 * @param UrlPolicy $policy  Policy.
	 * @return array List of { url, source, post_id, exclude }.
	 */
	public static function from_sitemaps( Fetcher $fetcher, UrlPolicy $policy ) {
		$base  = $policy->home_scheme() . '://' . $policy->home_host();
		$queue = array( $base . '/wp-sitemap.xml', $base . '/sitemap_index.xml', $base . '/sitemap.xml' );
		$seen  = array();
		$out   = array();
		$read  = 0;
		while ( ! empty( $queue ) && $read < self::MAX_SITEMAPS && count( $out ) < self::MAX_SITEMAP_URLS ) {
			$url = array_shift( $queue );
			if ( isset( $seen[ $url ] ) ) {
				continue;
			}
			$seen[ $url ] = true;
			$result       = $fetcher->fetch( $url );
			++$read;
			if ( 'ok' !== $result['outcome'] ) {
				continue;
			}
			$parsed = self::parse_sitemap( $result['body'] );
			foreach ( $parsed['sitemaps'] as $child ) {
				if ( $policy->check_url( $child )['ok'] ) {
					$queue[] = $child;
				}
			}
			foreach ( $parsed['urls'] as $loc ) {
				if ( count( $out ) >= self::MAX_SITEMAP_URLS ) {
					break;
				}
				$out[] = array(
					'url'     => $loc,
					'source'  => 'sitemap',
					'post_id' => 0,
					'exclude' => '',
				);
			}
			if ( ! empty( $parsed['urls'] ) || ! empty( $parsed['sitemaps'] ) ) {
				// Found a working index; do not also read the fallbacks.
				$queue = array_values(
					array_filter(
						$queue,
						static function ( $q ) use ( $base ) {
							return ! in_array( $q, array( $base . '/sitemap_index.xml', $base . '/sitemap.xml' ), true );
						}
					)
				);
			}
		}
		return $out;
	}

	/**
	 * Read <loc> values from a sitemap or sitemap index without an XML
	 * parser, so entity expansion is never possible.
	 *
	 * @param string $xml Document.
	 * @return array { urls, sitemaps }
	 */
	public static function parse_sitemap( $xml ) {
		$xml = (string) $xml;
		$out = array(
			'urls'     => array(),
			'sitemaps' => array(),
		);
		$is_index = (bool) preg_match( '/<sitemapindex[\s>]/i', $xml );
		if ( preg_match_all( '#<loc>\s*(.*?)\s*</loc>#is', $xml, $m ) ) {
			foreach ( $m[1] as $loc ) {
				$loc = html_entity_decode( preg_replace( '/^<!\[CDATA\[(.*)\]\]>$/s', '$1', trim( $loc ) ), ENT_QUOTES | ENT_XML1, 'UTF-8' );
				if ( '' === $loc ) {
					continue;
				}
				if ( $is_index ) {
					$out['sitemaps'][] = $loc;
				} else {
					$out['urls'][] = $loc;
				}
			}
		}
		return $out;
	}

	/**
	 * Turn candidates into the frozen list: normalise, drop query strings
	 * and fragments, apply the request policy, de-duplicate, cap.
	 *
	 * @param array     $candidates Candidates.
	 * @param UrlPolicy $policy     Policy.
	 * @param int       $max_urls   Cap.
	 * @return array { urls: list of { url, url_key, source, post_id, coverage, reason }, excluded_by_reason }
	 */
	public static function freeze( array $candidates, UrlPolicy $policy, $max_urls ) {
		$list     = array();
		$keys     = array();
		$counts   = array();
		$included = 0;
		foreach ( $candidates as $c ) {
			// Permalinks WordPress generated itself keep their query string, so
			// plain permalinks (?p=12) work; the request policy still refuses
			// action, nonce and REST queries. Other sources lose it (F6).
			$from_wp = 'home' === $c['source'] || 0 === strpos( (string) $c['source'], 'post:' );
			$url     = $from_wp ? (string) preg_replace( '/#.*$/s', '', trim( (string) $c['url'] ) ) : self::clean( (string) $c['url'] );
			$key = Evaluator::url_key( $url );
			if ( '' === $url || isset( $keys[ $key ] ) ) {
				continue;
			}
			$keys[ $key ] = true;
			$reason       = (string) $c['exclude'];
			if ( '' === $reason ) {
				$check  = $policy->check_url( $url );
				$reason = $check['ok'] ? '' : $check['reason'];
			}
			if ( '' === $reason && $included >= (int) $max_urls ) {
				$reason = 'url_cap';
			}
			if ( '' === $reason ) {
				++$included;
			} else {
				$counts[ $reason ] = isset( $counts[ $reason ] ) ? $counts[ $reason ] + 1 : 1;
			}
			$list[] = array(
				'url'      => $url,
				'url_key'  => sha1( $key ),
				'source'   => (string) $c['source'],
				'post_id'  => (int) $c['post_id'],
				'coverage' => '' === $reason ? 'pending' : 'excluded',
				'reason'   => $reason,
			);
		}
		return array(
			'urls'               => $list,
			'excluded_by_reason' => $counts,
			'included'           => $included,
		);
	}

	/**
	 * Strip query string and fragment, trim whitespace.
	 *
	 * @param string $url URL.
	 * @return string
	 */
	public static function clean( $url ) {
		$url = trim( $url );
		$url = (string) preg_replace( '/[?#].*$/s', '', $url );
		return $url;
	}

	/**
	 * Counts of content WordPress holds but the audit leaves out by design,
	 * recorded in the scope snapshot so every exclusion has a reason.
	 *
	 * @param array $settings Settings.
	 * @return array reason => count
	 */
	public static function status_exclusions( array $settings ) {
		$out = array();
		foreach ( (array) $settings['post_types'] as $type ) {
			$counts = wp_count_posts( $type );
			foreach ( array( 'draft', 'pending', 'private', 'future' ) as $status ) {
				if ( ! empty( $counts->$status ) ) {
					$key         = 'status_' . $status;
					$out[ $key ] = ( isset( $out[ $key ] ) ? $out[ $key ] : 0 ) + (int) $counts->$status;
				}
			}
		}
		return $out;
	}
}
