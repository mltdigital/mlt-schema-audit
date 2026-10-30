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
	 * Every site-wide rule over the per-page facts. The worker and the
	 * fixture tests both call this, so they run the same rules.
	 *
	 * @param array $pages run_url_id => site facts from Evaluator.
	 * @return array run_url_id => findings
	 */
	public static function evaluate( array $pages ) {
		$out = self::identity_conflicts( $pages );
		foreach ( array( self::split_identities( $pages ), self::page_identities( $pages ), self::dangling_refs( $pages ) ) as $more ) {
			foreach ( $more as $url_id => $findings ) {
				foreach ( $findings as $finding ) {
					$out[ $url_id ][] = $finding;
				}
			}
		}
		return $out;
	}

	/**
	 * A site-wide finding.
	 *
	 * @param string $rule_id Rule.
	 * @param string $confidence Confidence.
	 * @param array  $data    Fields.
	 * @return array
	 */
	private static function finding( $rule_id, $confidence, array $data ) {
		$rule = Rules::get( $rule_id );
		return array_merge(
			array(
				'rule_id'           => $rule_id,
				'rule_version'      => (int) $rule['version'],
				'outcome'           => 'review',
				'severity'          => $rule['severity'],
				'confidence'        => $confidence,
				'entity'            => '',
				'entity_type'       => '',
				'property'          => '',
				'block'             => -1,
				'path'              => '',
				'observed'          => '',
				'comparison'        => '',
				'snippet'           => '',
				'source'            => 'unknown',
				'source_confidence' => 'low',
				'site_wide'         => true,
				'support'           => array(),
			),
			$data
		);
	}

	/**
	 * SITE-002: one business under different @ids on different pages, with
	 * the same phone and postcode and nothing linking the identifiers.
	 *
	 * @param array $pages run_url_id => site facts.
	 * @return array run_url_id => findings
	 */
	public static function split_identities( array $pages ) {
		$by_signature = array();
		$links        = array();
		foreach ( $pages as $url_id => $facts ) {
			foreach ( isset( $facts['entities'] ) ? (array) $facts['entities'] : array() as $id => $entries ) {
				foreach ( $entries as $entry ) {
					foreach ( isset( $entry['links'] ) ? (array) $entry['links'] : array() as $target ) {
						$links[ $id ][ $target ] = true;
						$links[ $target ][ $id ] = true;
					}
					if ( empty( $entry['phones'] ) || empty( $entry['postcodes'] ) ) {
						continue;
					}
					$phones    = $entry['phones'];
					$postcodes = $entry['postcodes'];
					sort( $phones );
					sort( $postcodes );
					$by_signature[ implode( ',', $phones ) . '|' . implode( ',', $postcodes ) ][ $id ][ $url_id ] = $entry;
				}
			}
		}
		$out = array();
		foreach ( $by_signature as $signature => $ids ) {
			if ( count( $ids ) < 2 ) {
				continue;
			}
			uasort(
				$ids,
				static function ( $a, $b ) {
					return count( $b ) - count( $a );
				}
			);
			$names = array_keys( $ids );
			$main  = (string) $names[0];
			foreach ( array_slice( $names, 1 ) as $other ) {
				if ( isset( $links[ $other ][ $main ] ) ) {
					continue;
				}
				foreach ( $ids[ $other ] as $url_id => $entry ) {
					$out[ $url_id ][] = self::finding(
						'SITE-002',
						'medium',
						array(
							'entity'      => $other,
							'entity_type' => $entry['type'],
							'property'    => '@id',
							'block'       => (int) $entry['block'],
							'path'        => $entry['path'],
							'observed'    => $other,
							'comparison'  => 'Same telephone and postcode as ' . $main . ', with no link between them',
							'support'     => array_keys( $ids[ $main ] + $ids[ $other ] ),
						)
					);
				}
			}
		}
		return $out;
	}

	/**
	 * SITE-003: a WebSite or WebPage @id named differently on different
	 * pages, or one WebPage @id used for different page URLs.
	 *
	 * @param array $pages run_url_id => site facts.
	 * @return array run_url_id => findings
	 */
	public static function page_identities( array $pages ) {
		$seen = array();
		foreach ( $pages as $url_id => $facts ) {
			foreach ( isset( $facts['named'] ) ? (array) $facts['named'] : array() as $id => $entries ) {
				foreach ( $entries as $entry ) {
					if ( '' !== $entry['name'] ) {
						$seen[ $id ]['name'][ strtolower( trim( $entry['name'] ) ) ][ $url_id ] = $entry;
					}
					if ( 'WebPage' === $entry['kind'] && '' !== $entry['url'] ) {
						$seen[ $id ]['url'][ $entry['url'] ][ $url_id ] = $entry;
					}
				}
			}
		}
		$out = array();
		foreach ( $seen as $id => $fields ) {
			foreach ( $fields as $field => $values ) {
				if ( count( $values ) < 2 ) {
					continue;
				}
				uasort(
					$values,
					static function ( $a, $b ) {
						return count( $b ) - count( $a );
					}
				);
				$keys    = array_keys( $values );
				$common  = (string) $keys[0];
				$support = array();
				foreach ( $values as $pages_with ) {
					$support += $pages_with;
				}
				foreach ( array_slice( $keys, 1 ) as $value ) {
					foreach ( $values[ $value ] as $url_id => $entry ) {
						$out[ $url_id ][] = self::finding(
							'SITE-003',
							'high',
							array(
								'entity'      => $id,
								'entity_type' => $entry['kind'],
								'property'    => $field,
								'block'       => (int) $entry['block'],
								'path'        => $entry['path'],
								'observed'    => (string) $value,
								'comparison'  => sprintf( '%s on %d other page(s)', $common, count( $values[ $common ] ) ),
								'support'     => array_keys( $support ),
							)
						);
					}
				}
			}
		}
		return $out;
	}

	/**
	 * ID-003: an own-host @id referenced on a page and defined on no page of
	 * the site. Cross-page references that resolve are not reported.
	 *
	 * @param array $pages run_url_id => site facts.
	 * @return array run_url_id => findings
	 */
	public static function dangling_refs( array $pages ) {
		$defined = array();
		foreach ( $pages as $facts ) {
			foreach ( isset( $facts['ids'] ) ? (array) $facts['ids'] : array() as $id ) {
				$defined[ $id ] = true;
			}
		}
		$out = array();
		foreach ( $pages as $url_id => $facts ) {
			foreach ( isset( $facts['refs'] ) ? (array) $facts['refs'] : array() as $id => $where ) {
				if ( isset( $defined[ $id ] ) ) {
					continue;
				}
				$out[ $url_id ][] = self::finding(
					'ID-003',
					'medium',
					array(
						'entity'     => $id,
						'block'      => (int) $where['block'],
						'path'       => $where['path'],
						'observed'   => $id,
						'comparison' => 'Defined on no page this audit read.',
					)
				);
			}
		}
		return $out;
	}

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
			foreach ( array( 'phones', 'postcodes', 'name', 'logo', 'rating' ) as $field ) {
				$values = array();
				foreach ( $per_page as $url_id => $entries ) {
					foreach ( $entries as $entry ) {
						if ( 'name' === $field ) {
							$list = '' !== $entry['name'] ? array( strtolower( trim( $entry['name'] ) ) ) : array();
						} else {
							$list = isset( $entry[ $field ] ) ? (array) $entry[ $field ] : array();
						}
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
					'logo'      => 'logo',
					'rating'    => 'aggregateRating',
				);
				foreach ( array_slice( $keys, 1 ) as $value ) {
					foreach ( $values[ $value ] as $url_id => $entry ) {
						$out[ $url_id ][] = array(
							'rule_id'           => 'SITE-001',
							'rule_version'      => (int) $rule['version'],
							'outcome'           => 'review',
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
							'support'           => array_keys( $per_page ),
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
			'support'           => array(),
		);
	}

	/**
	 * Evidence behind each site-wide issue in this run: the pages whose facts
	 * the finding rests on (every page carrying the entity, not only the
	 * page that differs) and, for URL-004, the resource itself. The issue
	 * register clears a site-wide issue only when all of it is read again.
	 *
	 * @param array $pages run_url_id => site facts.
	 * @param array $urls  run_url_id => URL.
	 * @return array issue_key => sorted refs (page url_key, or resource:<url>)
	 */
	public static function evidence( array $pages, array $urls ) {
		$refs = array();
		$add  = static function ( $key, array $url_ids ) use ( &$refs, $urls ) {
			foreach ( $url_ids as $url_id ) {
				if ( isset( $urls[ $url_id ] ) ) {
					$refs[ $key ][ Evaluator::url_key( $urls[ $url_id ] ) ] = true;
				}
			}
		};
		foreach ( self::evaluate( $pages ) as $url_id => $findings ) {
			foreach ( $findings as $finding ) {
				$add( Comparator::issue_key( '', $finding ), array_merge( array( $url_id ), $finding['support'] ) );
			}
		}
		foreach ( self::resources( $pages ) as $url => $where_list ) {
			foreach ( $where_list as $where ) {
				$key                                = Comparator::issue_key( '', self::broken_resource( $url, $where, 404 ) );
				$refs[ $key ][ 'resource:' . $url ] = true;
				$add( $key, array( $where['url_id'] ) );
			}
		}
		foreach ( $refs as $key => $set ) {
			$list = array_keys( $set );
			sort( $list );
			$refs[ $key ] = $list;
		}
		return $refs;
	}

	/**
	 * Every own-host resource referenced by a page read in this run, with
	 * the outcome of its check. A resource referenced but not checked (over
	 * the cap, or the check did not finish) is "unchecked", which holds any
	 * issue that rests on it.
	 *
	 * @param array $pages    run_url_id => site facts (resources key used).
	 * @param array $outcomes Resource URL => fetch outcome, from the check.
	 * @return array url => outcome
	 */
	public static function resource_outcomes( array $pages, array $outcomes ) {
		$out = array();
		foreach ( $pages as $facts ) {
			foreach ( isset( $facts['resources'] ) ? array_keys( (array) $facts['resources'] ) : array() as $url ) {
				$out[ $url ] = isset( $outcomes[ $url ] ) ? (string) $outcomes[ $url ] : 'unchecked';
			}
		}
		return $out;
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
