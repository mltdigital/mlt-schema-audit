<?php
/**
 * Runs the page rules over one page's extraction.
 *
 * Returns only non-pass outcomes. A pass is the absence of a finding on a
 * page that was fetched and evaluated under a known rule-set version, which
 * is what lets a later run say "no longer detected".
 *
 * @package MLT\SchemaAudit
 */

namespace MLT\SchemaAudit\Engine;

defined( 'ABSPATH' ) || defined( 'MLTSA_TESTING' ) || exit;

/**
 * Evaluator.
 */
class Evaluator {

	/**
	 * Evidence snippet cap in characters (contract section 3, Proposed).
	 */
	const SNIPPET_CHARS = 500;

	/**
	 * Hosts that are never live (URL-001).
	 *
	 * @var array
	 */
	const STAGING_PATTERNS = array(
		'/\.(local|test|localhost|invalid|example|internal|lan)$/',
		'/^localhost$/',
		'/^(staging|stage|dev|develop|test|testing|uat|preprod|pre-prod|demo)[\.\-]/',
		'/\.(wpengine\.com|wpenginepowered\.com|kinsta\.cloud|pantheonsite\.io|flywheelsites\.com|cloudwaysapps\.com|wpstagecoach\.com|instawp\.xyz|ngrok\.io|ngrok-free\.app)$/',
	);

	/**
	 * Context.
	 *
	 * @var array
	 */
	private $ctx;

	/**
	 * Findings for the page.
	 *
	 * @var array
	 */
	private $findings = array();

	/**
	 * Entity graph.
	 *
	 * @var Graph
	 */
	private $graph;

	/**
	 * Page facts.
	 *
	 * @var PageFacts
	 */
	private $facts;

	/**
	 * Blocks.
	 *
	 * @var array
	 */
	private $blocks;

	/**
	 * Constructor.
	 *
	 * @param array $context { page_url, own_hosts, home_scheme, staging_patterns (extra regexes),
	 *                         approved_phones (NSNs), approved_names }.
	 */
	public function __construct( array $context ) {
		$this->ctx = array_merge(
			array(
				'page_url'         => '',
				'own_hosts'        => array(),
				'home_scheme'      => 'https',
				'staging_patterns' => array(),
				'approved_phones'  => array(),
				'approved_names'   => array(),
			),
			$context
		);
	}

	/**
	 * Evaluate a page.
	 *
	 * @param array $extraction Extractor output.
	 * @return array { findings, graph, facts (compact facts for site rules) }
	 */
	public function evaluate( array $extraction ) {
		$this->findings = array();
		$this->blocks   = $extraction['blocks'];
		$this->facts    = new PageFacts( $extraction );
		$this->graph    = new Graph( $this->blocks, $this->ctx['page_url'] );

		$this->syntax_rules();
		$this->identity_rules();
		$this->fact_rules();
		$this->url_rules( (string) $extraction['canonical'] );
		$this->feature_rules();

		$parsed = 0;
		foreach ( $this->blocks as $block ) {
			$parsed += 'ok' === $block['parse'] ? 1 : 0;
		}
		if ( empty( $this->blocks ) ) {
			$this->add( 'REL-001', 'review', 'high', array( 'observed' => '0 JSON-LD blocks', 'comparison' => sprintf( 'Microdata: %d, RDFa: %d', (int) $extraction['microdata'], (int) $extraction['rdfa'] ) ) );
		}
		if ( (int) $extraction['microdata'] > 0 || (int) $extraction['rdfa'] > 0 ) {
			$this->add( 'REL-002', 'review', 'high', array( 'observed' => sprintf( 'Microdata items: %d, RDFa attributes: %d', (int) $extraction['microdata'], (int) $extraction['rdfa'] ) ) );
		}

		return array(
			'findings' => $this->findings,
			'site'     => $this->site_facts(),
			'parsed'   => $parsed,
		);
	}

	/**
	 * Syntax and structure.
	 */
	private function syntax_rules() {
		foreach ( $this->blocks as $block ) {
			$base = array(
				'block'             => $block['index'],
				'path'              => '$',
				'entity'            => 'block:' . $block['source'] . ':' . $block['index'],
				'source'            => $block['source'],
				'source_confidence' => $block['source_confidence'],
			);
			if ( 'empty' === $block['parse'] ) {
				$this->add( 'SYN-004', 'fail', 'high', $base + array( 'observed' => '(empty)' ) );
				continue;
			}
			if ( 'too_large' === $block['parse'] ) {
				$this->add( 'SYN-003', 'review', 'high', $base + array( 'observed' => $block['error'] ) );
				continue;
			}
			if ( 'error' === $block['parse'] ) {
				if ( $block['entity_encoded'] ) {
					$this->add( 'SYN-002', 'fail', 'high', $base + array( 'observed' => $block['error'], 'snippet' => $block['raw'] ) );
				} elseif ( 0 === strpos( $block['error'], 'Nesting deeper' ) ) {
					$this->add( 'SYN-003', 'review', 'high', $base + array( 'observed' => $block['error'] ) );
				} else {
					$this->add( 'SYN-001', 'fail', 'high', $base + array( 'observed' => $block['error'], 'snippet' => $block['raw'] ) );
				}
				continue;
			}
			$context = isset( $this->graph->contexts[ $block['index'] ] ) ? $this->graph->contexts[ $block['index'] ] : 'missing';
			if ( 'schema_org' !== $context ) {
				$raw_context = is_array( $block['data'] ) && isset( $block['data']['@context'] ) ? $block['data']['@context'] : null;
				$this->add(
					'SYN-005',
					'missing' === $context ? 'fail' : 'review',
					'high',
					$base + array(
						'path'     => "$['@context']",
						'observed' => null === $raw_context ? '(none)' : self::scalar( $raw_context ),
					)
				);
			}
		}
		if ( $this->graph->capped ) {
			$this->add( 'SYN-003', 'review', 'high', array( 'observed' => sprintf( 'More than %d entities on the page; analysis stopped at the limit.', Graph::MAX_NODES ) ) );
		}
		foreach ( $this->graph->nodes as $node ) {
			if ( $node['top_level'] && empty( $node['types'] ) && ! $node['is_ref'] && '' === $node['id'] ) {
				$this->add( 'SYN-006', 'review', 'medium', $this->node_base( $node ) );
			}
			foreach ( $node['types'] as $type ) {
				if ( ! preg_match( '/^[A-Z][A-Za-z0-9]*$/', $type ) && ! preg_match( '#^https?://#', $type ) ) {
					$this->add( 'SYN-007', 'review', 'high', $this->node_base( $node, "['@type']" ) + array( 'observed' => $type ) );
				}
			}
		}
	}

	/**
	 * Identity and relationships.
	 */
	private function identity_rules() {
		// ID-001: same @id, conflicting values on one page.
		foreach ( $this->graph->by_id as $id => $keys ) {
			$defs = $this->graph->definitions( $id );
			if ( count( $defs ) < 2 ) {
				continue;
			}
			foreach ( array( 'name', 'legalName', 'telephone', 'url', 'email', 'postalCode', 'streetAddress' ) as $prop ) {
				$seen = array();
				foreach ( $defs as $def ) {
					foreach ( self::prop_values( $def['props'], $prop ) as $value ) {
						$norm = self::normalise_for( $prop, $value );
						if ( '' !== $norm && ! isset( $seen[ $norm ] ) ) {
							$seen[ $norm ] = array( $value, $def );
						}
					}
				}
				if ( count( $seen ) > 1 ) {
					$pairs = array_values( $seen );
					$this->add(
						'ID-001',
						'review',
						'high',
						$this->node_base( $pairs[0][1], "['" . $prop . "']" ) + array(
							'property'   => $prop,
							'observed'   => $pairs[0][0] . ' (block ' . $pairs[0][1]['block'] . ')',
							'comparison' => $pairs[1][0] . ' (block ' . $pairs[1][1]['block'] . ')',
						)
					);
				}
			}
		}

		// ID-002: the page's own business identified on another site.
		foreach ( $this->primary_businesses() as $node ) {
			$merged  = $this->merged_props( $node );
			$hosts   = array();
			$foreign = array();
			foreach ( array( '@id' => $node['id'], 'url' => isset( $merged['url'] ) && is_string( $merged['url'] ) ? $merged['url'] : '' ) as $label => $value ) {
				$host = $value ? strtolower( (string) parse_url( $value, PHP_URL_HOST ) ) : ''; // phpcs:ignore WordPress.WP.AlternativeFunctions.parse_url_parse_url
				if ( '' === $host ) {
					continue;
				}
				$hosts[ $label ] = $host;
				if ( ! $this->is_own_host( $host ) ) {
					$foreign[ $label ] = $value;
				}
			}
			if ( ! empty( $foreign ) ) {
				$this->add(
					'ID-002',
					'review',
					count( $foreign ) === count( $hosts ) ? 'high' : 'medium',
					$this->node_base( $node ) + array(
						'observed'   => implode( '; ', array_map( array( __CLASS__, 'label_pair' ), array_keys( $foreign ), $foreign ) ),
						'comparison' => 'Site host: ' . implode( ', ', $this->ctx['own_hosts'] ),
					)
				);
			}
		}

		// ID-003: reference to an own-host entity never defined on the page.
		$reported = array();
		foreach ( $this->graph->nodes as $node ) {
			if ( ! $node['is_ref'] || isset( $reported[ $node['id'] ] ) ) {
				continue;
			}
			$host = strtolower( (string) parse_url( $node['id'], PHP_URL_HOST ) ); // phpcs:ignore WordPress.WP.AlternativeFunctions.parse_url_parse_url
			if ( $this->is_own_host( $host ) && empty( $this->graph->definitions( $node['id'] ) ) ) {
				$reported[ $node['id'] ] = true;
				$this->add( 'ID-003', 'review', 'medium', $this->node_base( $node ) + array( 'observed' => $node['id'] ) );
			}
		}
	}

	/**
	 * Published facts, corroborated only against the page's visible text.
	 */
	private function fact_rules() {
		$approved = array_values( array_filter( array_map( array( PageFacts::class, 'phone_nsn' ), (array) $this->ctx['approved_phones'] ) ) );
		$done     = array();
		foreach ( $this->graph->nodes as $node ) {
			if ( $node['is_ref'] ) {
				continue;
			}
			$types = $this->graph->all_types( $node );
			if ( Vocabulary::is_business( $types ) || Vocabulary::is_a( $types, 'Place' ) || Vocabulary::is_a( $types, 'ContactPoint' ) ) {
				foreach ( self::prop_values( $node['props'], 'telephone' ) as $phone ) {
					$key = 'tel|' . $node['key'] . '|' . $phone;
					if ( isset( $done[ $key ] ) ) {
						continue;
					}
					$done[ $key ] = true;
					$base         = $this->node_base( $node, "['telephone']" ) + array(
						'property' => 'telephone',
						'observed' => $phone,
					);
					$nsn          = PageFacts::phone_nsn( $phone );
					if ( '' === $nsn ) {
						$this->add( 'FACT-004', 'fail', 'high', $base );
						continue;
					}
					if ( ! empty( $approved ) && ! in_array( $nsn, $approved, true ) ) {
						$this->add( 'FACT-006', 'review', 'high', $base + array( 'comparison' => 'Approved: ' . implode( ', ', (array) $this->ctx['approved_phones'] ) ) );
					}
					if ( ! $this->facts->has_phone( $phone ) && ! in_array( $nsn, $approved, true ) ) {
						$this->add(
							'FACT-001',
							'review',
							'medium',
							$base + array( 'comparison' => empty( $this->facts->phones ) ? 'No phone numbers found in the page text.' : 'Numbers on the page: ' . implode( ', ', array_map( array( __CLASS__, 'display_nsn' ), array_slice( $this->facts->phones, 0, 10 ) ) ) )
						);
					}
				}
			}
			if ( Vocabulary::is_a( $types, 'PostalAddress' ) || ( empty( $types ) && isset( $node['props']['postalCode'] ) ) ) {
				foreach ( self::prop_values( $node['props'], 'postalCode' ) as $postcode ) {
					if ( '' !== PageFacts::postcode_compact( $postcode ) && ! $this->facts->has_postcode( $postcode ) ) {
						$this->add(
							'FACT-002',
							'review',
							'medium',
							$this->node_base( $node, "['postalCode']" ) + array(
								'property'   => 'postalCode',
								'observed'   => $postcode,
								'comparison' => empty( $this->facts->postcodes ) ? 'No postcodes found in the page text.' : 'Postcodes on the page: ' . implode( ', ', array_slice( $this->facts->postcodes, 0, 10 ) ),
							)
						);
					}
				}
			}
		}
		// Inline addresses without @type are not graph nodes; check them on their parent.
		foreach ( $this->graph->nodes as $node ) {
			if ( isset( $node['props']['address'] ) && is_array( $node['props']['address'] ) ) {
				$addresses = Graph::is_list( $node['props']['address'] ) ? $node['props']['address'] : array( $node['props']['address'] );
				foreach ( $addresses as $i => $address ) {
					if ( ! is_array( $address ) || isset( $address['@type'] ) || isset( $address['@id'] ) || ! isset( $address['postalCode'] ) || ! is_string( $address['postalCode'] ) ) {
						continue;
					}
					$postcode = $address['postalCode'];
					if ( '' !== PageFacts::postcode_compact( $postcode ) && ! $this->facts->has_postcode( $postcode ) ) {
						$this->add( 'FACT-002', 'review', 'medium', $this->node_base( $node, "['address']['postalCode']" ) + array( 'property' => 'postalCode', 'observed' => $postcode ) );
					}
				}
			}
		}

		// FACT-003: the page's own business named on the page.
		$names = array_map( 'strtolower', (array) $this->ctx['approved_names'] );
		foreach ( $this->primary_businesses() as $node ) {
			$merged = $this->merged_props( $node );
			if ( ! isset( $merged['name'] ) || ! is_string( $merged['name'] ) || '' === trim( $merged['name'] ) ) {
				continue;
			}
			if ( in_array( strtolower( trim( $merged['name'] ) ), $names, true ) ) {
				continue;
			}
			if ( ! $this->facts->has_name( $merged['name'] ) ) {
				$this->add( 'FACT-003', 'review', 'medium', $this->node_base( $node, "['name']" ) + array( 'property' => 'name', 'observed' => $merged['name'], 'comparison' => 'Page title: ' . $this->facts->title ) );
			}
		}

		// FACT-005: the person a profile page is about.
		foreach ( $this->graph->nodes as $node ) {
			if ( $node['is_ref'] || ! Vocabulary::is_a( $this->graph->all_types( $node ), 'ProfilePage' ) ) {
				continue;
			}
			foreach ( array( 'mainEntity', 'about' ) as $prop ) {
				if ( ! isset( $node['props'][ $prop ] ) ) {
					continue;
				}
				foreach ( $this->graph->resolve( $node['props'][ $prop ] ) as $person ) {
					if ( Vocabulary::is_a( $person['types'], 'Person' ) && isset( $person['props']['name'] ) && is_string( $person['props']['name'] ) && ! $this->facts->has_name( $person['props']['name'] ) ) {
						$this->add( 'FACT-005', 'review', 'medium', $this->node_base( $person, "['name']" ) + array( 'property' => 'name', 'observed' => $person['props']['name'], 'comparison' => 'Page title: ' . $this->facts->title ) );
					}
				}
			}
		}
	}

	/**
	 * URLs and resources.
	 *
	 * @param string $canonical Canonical link href.
	 */
	private function url_rules( $canonical ) {
		$patterns = array_merge( self::STAGING_PATTERNS, (array) $this->ctx['staging_patterns'] );
		$seen     = array();
		foreach ( $this->blocks as $block ) {
			if ( ! is_array( $block['data'] ) || 'ok' !== $block['parse'] ) {
				continue;
			}
			foreach ( self::string_values( $block['data'], '$' ) as $item ) {
				list( $path, $prop, $value ) = $item;
				$base                        = array(
					'block'             => $block['index'],
					'path'              => $path,
					'entity'            => 'url:' . $value,
					'property'          => $prop,
					'observed'          => $value,
					'source'            => $block['source'],
					'source_confidence' => $block['source_confidence'],
				);
				if ( preg_match( '#^(https?:)?//([^/\s?\#:]+)#i', $value, $m ) ) {
					$host = strtolower( $m[2] );
					if ( ! $this->is_own_host( $host ) && ! isset( $seen[ 'stg|' . $value ] ) ) {
						foreach ( $patterns as $pattern ) {
							if ( @preg_match( $pattern, $host ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Staff-entered patterns are validated on save; a bad one must not stop the run.
								$seen[ 'stg|' . $value ] = true;
								$this->add( 'URL-001', 'fail', 'high', $base + array( 'comparison' => 'Matches ' . $pattern ) );
								break;
							}
						}
					}
					if ( 'https' === $this->ctx['home_scheme'] && 0 === stripos( $value, 'http://' ) && $this->is_own_host( $host ) && ! isset( $seen[ 'http|' . $value ] ) ) {
						$seen[ 'http|' . $value ] = true;
						$this->add( 'URL-002', 'review', 'high', $base );
					}
				}
				if ( in_array( $prop, array( 'url', 'sameAs', 'logo', 'image', 'contentUrl', 'thumbnailUrl', 'hasMap', 'item' ), true ) && ! isset( $seen[ 'bad|' . $value ] ) ) {
					if ( preg_match( '/\s/', trim( $value ) ) || false !== strpos( $value, '&amp;' ) || ! preg_match( '#^https?://[^/\s]+#i', trim( $value ) ) ) {
						$seen[ 'bad|' . $value ] = true;
						$this->add( 'URL-005', 'review', 'high', $base );
					}
				}
			}
		}

		// URL-003: the page's WebPage url against the canonical link.
		if ( '' !== $canonical ) {
			$canonical_norm = self::url_key( UrlPolicy::resolve_reference( $this->ctx['page_url'], $canonical ) );
			foreach ( $this->graph->nodes as $node ) {
				if ( $node['is_ref'] || ! $node['top_level'] || ! Vocabulary::is_a( $node['types'], 'WebPage' ) ) {
					continue;
				}
				$url = isset( $node['props']['url'] ) && is_string( $node['props']['url'] ) ? $node['props']['url'] : '';
				if ( '' === $url || ! $this->is_own_host( strtolower( (string) parse_url( $url, PHP_URL_HOST ) ) ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.parse_url_parse_url
					continue;
				}
				if ( self::url_key( $url ) !== $canonical_norm ) {
					$this->add( 'URL-003', 'review', 'high', $this->node_base( $node, "['url']" ) + array( 'property' => 'url', 'observed' => $url, 'comparison' => $canonical ) );
				}
			}
		}
	}

	/**
	 * Search feature requirements.
	 */
	private function feature_rules() {
		$done_address = array();
		foreach ( $this->primary_businesses() as $node ) {
			$merged = $this->merged_props( $node );
			foreach ( array( 'aggregateRating', 'review' ) as $prop ) {
				if ( ! empty( $merged[ $prop ] ) ) {
					$this->add( 'FEAT-001', 'review', 'high', $this->node_base( $node, "['" . $prop . "']" ) + array( 'property' => $prop, 'observed' => self::scalar( $merged[ $prop ] ) ) );
				}
			}
		}
		foreach ( $this->graph->nodes as $node ) {
			if ( $node['is_ref'] ) {
				continue;
			}
			$types = $node['types'];
			if ( Vocabulary::is_a( $types, 'FAQPage' ) ) {
				$questions = array();
				if ( isset( $node['props']['mainEntity'] ) ) {
					foreach ( $this->graph->resolve( $node['props']['mainEntity'] ) as $q ) {
						if ( Vocabulary::is_a( $q['types'], 'Question' ) ) {
							$questions[] = $q;
						}
					}
				}
				if ( empty( $questions ) ) {
					$this->add( 'FEAT-002', 'fail', 'high', $this->node_base( $node, "['mainEntity']" ) + array( 'property' => 'mainEntity', 'observed' => isset( $node['props']['mainEntity'] ) ? self::scalar( $node['props']['mainEntity'] ) : '(absent)' ) );
				}
				foreach ( array_slice( $questions, 0, 50 ) as $q ) {
					$name = isset( $q['props']['name'] ) && is_string( $q['props']['name'] ) ? $q['props']['name'] : '';
					if ( '' !== $name && ! $this->facts->has_phrase( $name ) ) {
						$this->add( 'FEAT-003', 'review', 'medium', $this->node_base( $q, "['name']" ) + array( 'property' => 'name', 'observed' => $name ) );
					}
				}
			}
			if ( Vocabulary::is_a( $types, 'AggregateRating' ) ) {
				$value = isset( $node['props']['ratingValue'] ) ? $node['props']['ratingValue'] : null;
				if ( null === $value || '' === $value ) {
					$this->add( 'FEAT-004', 'fail', 'high', $this->node_base( $node, "['ratingValue']" ) + array( 'property' => 'ratingValue', 'observed' => '(absent)' ) );
				} elseif ( ! is_numeric( is_string( $value ) ? trim( $value ) : $value ) ) {
					$this->add( 'FEAT-004', 'review', 'high', $this->node_base( $node, "['ratingValue']" ) + array( 'property' => 'ratingValue', 'observed' => self::scalar( $value ) ) );
				}
				if ( ! isset( $node['props']['ratingCount'] ) && ! isset( $node['props']['reviewCount'] ) ) {
					$this->add( 'FEAT-004', 'fail', 'high', $this->node_base( $node, "['ratingCount']" ) + array( 'property' => 'ratingCount', 'observed' => '(absent: neither ratingCount nor reviewCount)' ) );
				}
			}
			if ( Vocabulary::is_a( $types, 'BreadcrumbList' ) && isset( $node['props']['itemListElement'] ) && is_array( $node['props']['itemListElement'] ) ) {
				$items = Graph::is_list( $node['props']['itemListElement'] ) ? $node['props']['itemListElement'] : array( $node['props']['itemListElement'] );
				$last  = count( $items ) - 1;
				foreach ( $items as $i => $item ) {
					if ( ! is_array( $item ) ) {
						continue;
					}
					$missing = array();
					if ( ! isset( $item['position'] ) ) {
						$missing[] = 'position';
					}
					$has_name = isset( $item['name'] ) || ( isset( $item['item'] ) && is_array( $item['item'] ) && isset( $item['item']['name'] ) );
					if ( ! $has_name ) {
						$missing[] = 'name';
					}
					if ( $i < $last && ! isset( $item['item'] ) ) {
						$missing[] = 'item';
					}
					if ( ! empty( $missing ) ) {
						$this->add( 'FEAT-005', 'fail', 'high', $this->node_base( $node, "['itemListElement'][" . $i . ']' ) + array( 'property' => 'itemListElement', 'observed' => 'Missing: ' . implode( ', ', $missing ), 'snippet' => self::scalar( $item ) ) );
					}
				}
			}
			foreach ( array( 'image', 'logo' ) as $prop ) {
				if ( ! isset( $node['props'][ $prop ] ) ) {
					continue;
				}
				$values = Graph::is_list( $node['props'][ $prop ] ) ? $node['props'][ $prop ] : array( $node['props'][ $prop ] );
				foreach ( $values as $value ) {
					if ( is_string( $value ) ) {
						continue;
					}
					$ok = is_array( $value ) && ( Vocabulary::is_a( Graph::types_of( $value ), 'ImageObject' ) || isset( $value['url'] ) || isset( $value['contentUrl'] ) || isset( $value['@id'] ) );
					if ( ! $ok ) {
						$this->add( 'FEAT-006', 'fail', 'high', $this->node_base( $node, "['" . $prop . "']" ) + array( 'property' => $prop, 'observed' => self::scalar( $value ) ) );
					}
				}
			}
			if ( ( $node['top_level'] || $this->is_primary( $node ) ) && Vocabulary::is_a( $this->graph->all_types( $node ), 'LocalBusiness' ) ) {
				$merged = $this->merged_props( $node );
				$address_key = '' !== $node['id'] ? $node['id'] : 'k' . $node['key'];
				if ( empty( $merged['address'] ) && ! isset( $done_address[ $address_key ] ) ) {
					$done_address[ $address_key ] = true;
					$this->add( 'FEAT-007', 'review', 'high', $this->node_base( $node, "['address']" ) + array( 'property' => 'address', 'observed' => '(absent)' ) );
				}
			}
		}
	}

	/**
	 * Facts kept per page for site-wide rules: business entities by @id and
	 * own-host resources cited as images or logos.
	 *
	 * @return array
	 */
	private function site_facts() {
		$entities  = array();
		$resources = array();
		foreach ( $this->graph->nodes as $node ) {
			if ( $node['is_ref'] ) {
				continue;
			}
			$types = $this->graph->all_types( $node );
			if ( '' !== $node['id'] && Vocabulary::is_business( $types ) ) {
				$entry = array(
					'type'      => isset( $types[0] ) ? $types[0] : '',
					'name'      => isset( $node['props']['name'] ) && is_string( $node['props']['name'] ) ? $node['props']['name'] : '',
					'phones'    => array_values( array_filter( array_map( array( PageFacts::class, 'phone_nsn' ), self::prop_values( $node['props'], 'telephone' ) ) ) ),
					'postcodes' => array(),
					'path'      => $node['path'],
					'block'     => $node['block'],
				);
				foreach ( self::prop_values( $node['props'], 'postalCode' ) as $postcode ) {
					$compact = PageFacts::postcode_compact( $postcode );
					if ( '' !== $compact ) {
						$entry['postcodes'][] = $compact;
					}
				}
				$entities[ $node['id'] ][] = $entry;
			}
			foreach ( array( 'image', 'logo', 'contentUrl', 'thumbnailUrl' ) as $prop ) {
				if ( ! isset( $node['props'][ $prop ] ) ) {
					continue;
				}
				$values = Graph::is_list( $node['props'][ $prop ] ) ? $node['props'][ $prop ] : array( $node['props'][ $prop ] );
				foreach ( $values as $value ) {
					$url = is_string( $value ) ? $value : ( is_array( $value ) ? ( isset( $value['contentUrl'] ) && is_string( $value['contentUrl'] ) ? $value['contentUrl'] : ( isset( $value['url'] ) && is_string( $value['url'] ) ? $value['url'] : '' ) ) : '' );
					$host = strtolower( (string) parse_url( $url, PHP_URL_HOST ) ); // phpcs:ignore WordPress.WP.AlternativeFunctions.parse_url_parse_url
					if ( '' !== $url && $this->is_own_host( $host ) ) {
						$resources[ $url ] = array(
							'prop'  => $prop,
							'path'  => $node['path'] . "['" . $prop . "']",
							'block' => $node['block'],
						);
					}
				}
			}
		}
		return array(
			'entities'  => $entities,
			'resources' => $resources,
		);
	}

	/**
	 * Business entities the page presents as its own: top-level businesses,
	 * and businesses a WebSite or WebPage names as publisher, about or
	 * mainEntity, or a Service names as provider.
	 *
	 * @return array Nodes, one per @id (or per anonymous node).
	 */
	private function primary_businesses() {
		$out = array();
		foreach ( $this->graph->nodes as $node ) {
			if ( $node['is_ref'] ) {
				continue;
			}
			if ( Vocabulary::is_business( $this->graph->all_types( $node ) ) && $this->is_primary( $node ) ) {
				$key = '' !== $node['id'] ? $node['id'] : 'k' . $node['key'];
				if ( ! isset( $out[ $key ] ) ) {
					$out[ $key ] = $node;
				}
			}
		}
		return array_values( $out );
	}

	/**
	 * Whether a node is presented as the page's own business.
	 *
	 * @param array $node Node.
	 * @return bool
	 */
	private function is_primary( array $node ) {
		if ( $node['top_level'] ) {
			return true;
		}
		foreach ( $this->graph->nodes as $parent ) {
			$ptypes = $parent['types'];
			$props  = array();
			if ( Vocabulary::is_a( $ptypes, 'WebSite' ) || Vocabulary::is_a( $ptypes, 'WebPage' ) ) {
				$props = array( 'publisher', 'about', 'mainEntity' );
			} elseif ( Vocabulary::is_a( $ptypes, 'Service' ) ) {
				$props = array( 'provider' );
			}
			foreach ( $props as $prop ) {
				if ( ! isset( $parent['props'][ $prop ] ) ) {
					continue;
				}
				foreach ( $this->graph->resolve( $parent['props'][ $prop ] ) as $child ) {
					if ( ( '' !== $node['id'] && $child['id'] === $node['id'] ) || ( -1 !== $child['key'] && $child['key'] === $node['key'] ) ) {
						return true;
					}
					if ( -1 === $child['key'] && '' === $node['id'] && $parent['path'] . "['" . $prop . "']" === $node['path'] ) {
						return true;
					}
				}
			}
		}
		return false;
	}

	/**
	 * Properties of a node merged with every definition sharing its @id.
	 *
	 * @param array $node Node.
	 * @return array
	 */
	private function merged_props( array $node ) {
		$props = $node['props'];
		if ( '' !== $node['id'] ) {
			foreach ( $this->graph->definitions( $node['id'] ) as $def ) {
				$props = $props + $def['props'];
			}
		}
		return $props;
	}

	/**
	 * Whether a host belongs to the site.
	 *
	 * @param string $host Host.
	 * @return bool
	 */
	private function is_own_host( $host ) {
		return in_array( strtolower( (string) $host ), (array) $this->ctx['own_hosts'], true );
	}

	/**
	 * Location fields for a node.
	 *
	 * @param array  $node   Node.
	 * @param string $suffix Path suffix.
	 * @return array
	 */
	private function node_base( array $node, $suffix = '' ) {
		$name   = isset( $node['props']['name'] ) && is_string( $node['props']['name'] ) ? $node['props']['name'] : '';
		$type   = isset( $node['types'][0] ) ? $node['types'][0] : 'Thing';
		$block  = isset( $this->blocks[ $node['block'] ] ) ? $this->blocks[ $node['block'] ] : null;
		$entity = '' !== $node['id'] ? $node['id'] : 'anon:' . $type . ':' . ( '' !== $name ? strtolower( $name ) : $node['path'] );
		return array(
			'block'             => $node['block'],
			'path'              => $node['path'] . $suffix,
			'entity'            => $entity,
			'entity_type'       => implode( ', ', $node['types'] ),
			'snippet'           => self::scalar( $node['props'] ),
			'source'            => $block ? $block['source'] : 'unknown',
			'source_confidence' => $block ? $block['source_confidence'] : 'low',
		);
	}

	/**
	 * Record a finding.
	 *
	 * @param string $rule_id    Rule.
	 * @param string $outcome    fail|review|unavailable.
	 * @param string $confidence high|medium|low.
	 * @param array  $data       Location and values.
	 */
	private function add( $rule_id, $outcome, $confidence, array $data ) {
		$rule             = Rules::get( $rule_id );
		$this->findings[] = array(
			'rule_id'           => $rule_id,
			'rule_version'      => (int) $rule['version'],
			'outcome'           => $outcome,
			'severity'          => $rule['severity'],
			'confidence'        => $confidence,
			'entity'            => isset( $data['entity'] ) ? (string) $data['entity'] : 'page',
			'entity_type'       => isset( $data['entity_type'] ) ? (string) $data['entity_type'] : '',
			'property'          => isset( $data['property'] ) ? (string) $data['property'] : '',
			'block'             => isset( $data['block'] ) ? (int) $data['block'] : -1,
			'path'              => isset( $data['path'] ) ? (string) $data['path'] : '',
			'observed'          => self::cap( isset( $data['observed'] ) ? (string) $data['observed'] : '' ),
			'comparison'        => self::cap( isset( $data['comparison'] ) ? (string) $data['comparison'] : '' ),
			'snippet'           => self::cap( isset( $data['snippet'] ) ? (string) $data['snippet'] : '' ),
			'source'            => isset( $data['source'] ) ? (string) $data['source'] : 'unknown',
			'source_confidence' => isset( $data['source_confidence'] ) ? (string) $data['source_confidence'] : 'low',
		);
	}

	/**
	 * Cap evidence text at the snippet limit (multibyte safe).
	 *
	 * @param string $text Text.
	 * @return string
	 */
	public static function cap( $text ) {
		$text = (string) $text;
		if ( function_exists( 'mb_substr' ) ) {
			return mb_strlen( $text, 'UTF-8' ) > self::SNIPPET_CHARS ? mb_substr( $text, 0, self::SNIPPET_CHARS - 1, 'UTF-8' ) . '…' : $text;
		}
		return strlen( $text ) > self::SNIPPET_CHARS ? substr( $text, 0, self::SNIPPET_CHARS ) : $text;
	}

	/**
	 * Render any value as short text.
	 *
	 * @param mixed $value Value.
	 * @return string
	 */
	public static function scalar( $value ) {
		if ( is_string( $value ) ) {
			return $value;
		}
		if ( is_bool( $value ) ) {
			return $value ? 'true' : 'false';
		}
		if ( null === $value ) {
			return 'null';
		}
		return (string) json_encode( $value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PARTIAL_OUTPUT_ON_ERROR ); // phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode
	}

	/**
	 * String values of a property on a node, including inside an inline address.
	 *
	 * @param array  $props Node properties.
	 * @param string $prop  Property.
	 * @return array
	 */
	public static function prop_values( array $props, $prop ) {
		$out = array();
		$add = static function ( $value ) use ( &$out ) {
			foreach ( Graph::is_list( $value ) ? $value : array( $value ) as $v ) {
				if ( is_string( $v ) && '' !== trim( $v ) ) {
					$out[] = trim( $v );
				} elseif ( is_int( $v ) || is_float( $v ) ) {
					$out[] = (string) $v;
				}
			}
		};
		if ( isset( $props[ $prop ] ) ) {
			$add( $props[ $prop ] );
		}
		if ( in_array( $prop, array( 'postalCode', 'streetAddress' ), true ) && isset( $props['address'] ) && is_array( $props['address'] ) ) {
			foreach ( Graph::is_list( $props['address'] ) ? $props['address'] : array( $props['address'] ) as $address ) {
				if ( is_array( $address ) && isset( $address[ $prop ] ) ) {
					$add( $address[ $prop ] );
				}
			}
		}
		return array_values( array_unique( $out ) );
	}

	/**
	 * Normalise a value for conflict comparison.
	 *
	 * @param string $prop  Property.
	 * @param string $value Value.
	 * @return string
	 */
	private static function normalise_for( $prop, $value ) {
		if ( 'telephone' === $prop ) {
			$nsn = PageFacts::phone_nsn( $value );
			return '' !== $nsn ? $nsn : strtolower( trim( $value ) );
		}
		if ( 'postalCode' === $prop ) {
			$compact = PageFacts::postcode_compact( $value );
			return '' !== $compact ? $compact : strtolower( trim( $value ) );
		}
		if ( 'url' === $prop ) {
			return self::url_key( $value );
		}
		$value = html_entity_decode( strtolower( (string) $value ), ENT_QUOTES | ENT_HTML5, 'UTF-8' );
		$value = str_replace( ' and ', ' & ', $value );
		return trim( (string) preg_replace( '/\s+/', ' ', $value ) );
	}

	/**
	 * Comparable form of a URL: lower-case host, no scheme, no trailing slash, no fragment.
	 *
	 * @param string $url URL.
	 * @return string
	 */
	public static function url_key( $url ) {
		$url = (string) preg_replace( '/#.*$/', '', trim( (string) $url ) );
		$url = (string) preg_replace( '#^https?://#i', '', $url );
		$url = (string) preg_replace( '#^www\.#i', '', $url );
		$parts = explode( '/', $url, 2 );
		$url   = strtolower( $parts[0] ) . ( isset( $parts[1] ) ? '/' . $parts[1] : '' );
		return rtrim( $url, '/' );
	}

	/**
	 * Every string value in a decoded block with its path and property name.
	 *
	 * @param mixed  $data  Data.
	 * @param string $path  Path.
	 * @param string $prop  Property name.
	 * @param int    $depth Depth.
	 * @return array [ path, prop, value ]
	 */
	public static function string_values( $data, $path, $prop = '', $depth = 0 ) {
		$out = array();
		if ( $depth > Extractor::MAX_DEPTH || count( $out ) > 20000 ) {
			return $out;
		}
		if ( is_string( $data ) ) {
			return array( array( $path, $prop, $data ) );
		}
		if ( ! is_array( $data ) ) {
			return $out;
		}
		$is_list = Graph::is_list( $data );
		foreach ( $data as $key => $value ) {
			$child_path = $is_list ? $path . '[' . $key . ']' : $path . "['" . $key . "']";
			$child_prop = $is_list ? $prop : (string) $key;
			foreach ( self::string_values( $value, $child_path, $child_prop, $depth + 1 ) as $item ) {
				$out[] = $item;
			}
		}
		return $out;
	}

	/**
	 * Display a national significant number in 0-prefixed form.
	 *
	 * @param string $nsn NSN.
	 * @return string
	 */
	public static function display_nsn( $nsn ) {
		return '0' . $nsn;
	}

	/**
	 * "label: value" text.
	 *
	 * @param string $label Label.
	 * @param string $value Value.
	 * @return string
	 */
	public static function label_pair( $label, $value ) {
		return $label . ': ' . $value;
	}
}
