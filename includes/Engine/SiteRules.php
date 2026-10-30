<?php
/**
 * Rules that need the whole run: one business @id with different details on
 * different pages (SITE-001), and own-host images that return 404 or 410
 * (URL-004).
 *
 * @package MLT\SchemaAudit
 */

namespace MLT\SchemaAudit\Engine;

defined( 'ABSPATH' ) || defined( 'MLTSA_TESTING' ) || exit;

/**
 * SiteRules.
 */
class SiteRules {

	/**
	 * Most distinct resources checked per run (Proposed).
	 */
	const MAX_RESOURCES = 200;

	/**
	 * SITE-001 over the per-page entity facts.
	 *
	 * @param array $pages run_url_id => site facts from Evaluator (entities key used).
	 * @return array run_url_id => findings
	 */
	public static function identity_conflicts( array $pages ) {
		$by_id = array();
		foreach ( $pages as $url_id => $facts ) {
			if ( empty( $facts['entities'] ) ) {
				continue;
			}
			foreach ( $facts['entities'] as $id => $entries ) {
				foreach ( $entries as $entry ) {
					$by_id[ $id ][ $url_id ][] = $entry;
				}
			}
		}

		$rule = Rules::get( 'SITE-001' );
		$out  = array();
		foreach ( $by_id as $id => $per_page ) {
			if ( count( $per_page ) < 2 ) {
				continue;
			}
			foreach ( array( 'phones', 'postcodes', 'name' ) as $field ) {
				$values = array();
				foreach ( $per_page as $url_id => $entries ) {
					foreach ( $entries as $entry ) {
						$list = 'name' === $field ? ( '' !== $entry['name'] ? array( strtolower( trim( $entry['name'] ) ) ) : array() ) : $entry[ $field ];
						if ( empty( $list ) ) {
							continue;
						}
						sort( $list );
						$values[ implode( ' | ', $list ) ][ $url_id ] = $entry;
					}
				}
				if ( count( $values ) < 2 ) {
					continue;
				}
				// Most common value is the comparison; every page with a
				// different value gets an occurrence of one site-wide issue.
				uasort(
					$values,
					static function ( $a, $b ) {
						return count( $b ) - count( $a );
					}
				);
				$keys    = array_keys( $values );
				$common  = (string) $keys[0];
				$display = array(
					'phones'    => 'telephone',
					'postcodes' => 'postalCode',
					'name'      => 'name',
				);
				foreach ( array_slice( $keys, 1 ) as $value ) {
					foreach ( $values[ $value ] as $url_id => $entry ) {
						$out[ $url_id ][] = array(
							'rule_id'           => 'SITE-001',
							'rule_version'      => (int) $rule['version'],
							'outcome'           => 'fail',
							'severity'          => $rule['severity'],
							'confidence'        => 'name' === $field ? 'medium' : 'high',
							'entity'            => $id,
							'entity_type'       => $entry['type'],
							'property'          => $display[ $field ],
							'block'             => (int) $entry['block'],
							'path'              => $entry['path'],
							'observed'          => self::show( $field, (string) $value ),
							'comparison'        => sprintf( '%s on %d other page(s)', self::show( $field, $common ), count( $values[ $common ] ) ),
							'snippet'           => '',
							'source'            => 'unknown',
							'source_confidence' => 'low',
							'site_wide'         => true,
						);
					}
				}
			}
		}
		return $out;
	}

	/**
	 * Distinct own-host resources across the run, capped.
	 *
	 * @param array $pages run_url_id => site facts (resources key used).
	 * @return array url => list of { url_id, prop, path, block }
	 */
	public static function resources( array $pages ) {
		$out = array();
		foreach ( $pages as $url_id => $facts ) {
			if ( empty( $facts['resources'] ) ) {
				continue;
			}
			foreach ( $facts['resources'] as $url => $where ) {
				if ( ! isset( $out[ $url ] ) && count( $out ) >= self::MAX_RESOURCES ) {
					continue;
				}
				$out[ $url ][] = array( 'url_id' => $url_id ) + $where;
			}
		}
		return $out;
	}

	/**
	 * URL-004 finding for one broken resource on one page.
	 *
	 * @param string $url    Resource URL.
	 * @param array  $where  { prop, path, block }.
	 * @param int    $status HTTP status (404 or 410).
	 * @return array
	 */
	public static function broken_resource( $url, array $where, $status ) {
		$rule = Rules::get( 'URL-004' );
		return array(
			'rule_id'           => 'URL-004',
			'rule_version'      => (int) $rule['version'],
			'outcome'           => 'fail',
			'severity'          => $rule['severity'],
			'confidence'        => 'high',
			'entity'            => 'resource:' . $url,
			'entity_type'       => '',
			'property'          => $where['prop'],
			'block'             => (int) $where['block'],
			'path'              => $where['path'],
			'observed'          => $url,
			'comparison'        => 'HTTP ' . (int) $status,
			'snippet'           => '',
			'source'            => 'unknown',
			'source_confidence' => 'low',
			'site_wide'         => true,
		);
	}

	/**
	 * Display a stored value.
	 *
	 * @param string $field Field.
	 * @param string $value Value.
	 * @return string
	 */
	private static function show( $field, $value ) {
		if ( 'phones' !== $field ) {
			return $value;
		}
		return implode( ' | ', array_map( array( Evaluator::class, 'display_nsn' ), explode( ' | ', $value ) ) );
	}
}
