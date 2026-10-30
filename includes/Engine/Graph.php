<?php
/**
 * Index of every entity in a page's JSON-LD blocks.
 *
 * Walks objects, arrays, @graph and nested values with a node cap (F4).
 * Decoded JSON is a tree, so walking cannot loop; @id references are only
 * followed through resolve(), which keeps a visited set, so reference cycles
 * (which are legal JSON-LD) cannot loop either.
 *
 * Remote @context documents are never fetched (F5). Only schema.org contexts
 * are recognised; anything else is recorded as unsupported.
 *
 * @package MLT\SchemaAudit
 */

namespace MLT\SchemaAudit\Engine;

defined( 'ABSPATH' ) || defined( 'MLTSA_TESTING' ) || exit;

/**
 * Graph.
 */
class Graph {

	/**
	 * Most nodes indexed per page (F4, Proposed).
	 */
	const MAX_NODES = 5000;

	/**
	 * Nodes: each { key, id, types, props, block, path, top_level, context }.
	 *
	 * @var array
	 */
	public $nodes = array();

	/**
	 * Nodes grouped by resolved @id.
	 *
	 * @var array
	 */
	public $by_id = array();

	/**
	 * Context status per block index: schema_org, missing, unsupported.
	 *
	 * @var array
	 */
	public $contexts = array();

	/**
	 * True when the node cap was reached and indexing stopped.
	 *
	 * @var bool
	 */
	public $capped = false;

	/**
	 * Page URL, used as the base for relative @id values.
	 *
	 * @var string
	 */
	private $base;

	/**
	 * Build the index from extracted blocks.
	 *
	 * @param array  $blocks Blocks from Extractor (only parsed ones are walked).
	 * @param string $base   Page URL.
	 */
	public function __construct( array $blocks, $base ) {
		$this->base = (string) $base;
		foreach ( $blocks as $block ) {
			if ( 'ok' !== $block['parse'] || ! is_array( $block['data'] ) ) {
				continue;
			}
			$data    = $block['data'];
			$context = self::context_status( self::is_list( $data ) ? null : ( isset( $data['@context'] ) ? $data['@context'] : null ) );
			if ( self::is_list( $data ) ) {
				// A top-level array: each member carries its own context.
				$statuses = array();
				foreach ( $data as $item ) {
					$statuses[] = self::context_status( is_array( $item ) && isset( $item['@context'] ) ? $item['@context'] : null );
				}
				$context = in_array( 'unsupported', $statuses, true ) ? 'unsupported' : ( in_array( 'missing', $statuses, true ) ? 'missing' : 'schema_org' );
			}
			$this->contexts[ $block['index'] ] = $context;
			$this->walk( $data, (int) $block['index'], '$', true, 0 );
		}
	}

	/**
	 * Recognise schema.org contexts without fetching anything.
	 *
	 * @param mixed $context @context value.
	 * @return string schema_org|missing|unsupported
	 */
	public static function context_status( $context ) {
		if ( null === $context || '' === $context ) {
			return 'missing';
		}
		if ( is_string( $context ) ) {
			return preg_match( '#^https?://schema\.org(/|/docs/jsonldcontext\.json(ld)?)?$#i', trim( $context ) ) ? 'schema_org' : 'unsupported';
		}
		if ( is_array( $context ) ) {
			if ( self::is_list( $context ) ) {
				$found = false;
				foreach ( $context as $item ) {
					$status = self::context_status( $item );
					if ( 'unsupported' === $status && ! is_array( $item ) ) {
						return 'unsupported';
					}
					$found = $found || 'schema_org' === $status;
				}
				return $found ? 'schema_org' : 'unsupported';
			}
			if ( isset( $context['@vocab'] ) && is_string( $context['@vocab'] ) && preg_match( '#^https?://schema\.org/?$#i', $context['@vocab'] ) ) {
				return 'schema_org';
			}
			return 'unsupported';
		}
		return 'unsupported';
	}

	/**
	 * Walk a value and index nodes.
	 *
	 * @param mixed  $value     Value.
	 * @param int    $block     Block index.
	 * @param string $path      JSON path.
	 * @param bool   $top_level Whether this is a top-level entity.
	 * @param int    $depth     Depth.
	 */
	private function walk( $value, $block, $path, $top_level, $depth ) {
		if ( ! is_array( $value ) || $this->capped || $depth > Extractor::MAX_DEPTH ) {
			return;
		}
		if ( self::is_list( $value ) ) {
			foreach ( $value as $i => $item ) {
				$this->walk( $item, $block, $path . '[' . $i . ']', $top_level, $depth + 1 );
			}
			return;
		}
		if ( isset( $value['@graph'] ) && is_array( $value['@graph'] ) ) {
			$this->walk( $value['@graph'], $block, $path . "['@graph']", true, $depth + 1 );
		}
		if ( isset( $value['@type'] ) || isset( $value['@id'] ) ) {
			if ( count( $this->nodes ) >= self::MAX_NODES ) {
				$this->capped = true;
				return;
			}
			$id    = isset( $value['@id'] ) && is_string( $value['@id'] ) ? $this->resolve_id( $value['@id'] ) : '';
			$types = self::types_of( $value );
			$props = $value;
			unset( $props['@graph'], $props['@context'] );
			$node          = array(
				'key'       => count( $this->nodes ),
				'id'        => $id,
				'types'     => $types,
				'props'     => $props,
				'block'     => $block,
				'path'      => $path,
				'top_level' => $top_level,
				'is_ref'    => '' !== $id && 1 === count( $props ),
			);
			$this->nodes[] = $node;
			if ( '' !== $id ) {
				$this->by_id[ $id ][] = $node['key'];
			}
		}
		foreach ( $value as $prop => $child ) {
			if ( '@graph' === $prop || '@context' === $prop || ! is_array( $child ) ) {
				continue;
			}
			$this->walk( $child, $block, $path . "['" . $prop . "']", false, $depth + 1 );
		}
	}

	/**
	 * Resolve an @id against the page URL. Blank node ids are kept as is.
	 *
	 * @param string $id Raw @id.
	 * @return string
	 */
	public function resolve_id( $id ) {
		$id = trim( (string) $id );
		if ( '' === $id || 0 === strpos( $id, '_:' ) ) {
			return $id;
		}
		return UrlPolicy::resolve_reference( $this->base, $id );
	}

	/**
	 * Types declared on a node, without a schema.org prefix.
	 *
	 * @param array $node Node.
	 * @return array
	 */
	public static function types_of( array $node ) {
		$types = array();
		$raw   = isset( $node['@type'] ) ? (array) $node['@type'] : array();
		foreach ( $raw as $type ) {
			if ( is_string( $type ) && '' !== trim( $type ) ) {
				$types[] = (string) preg_replace( '#^(?:https?://schema\.org/|schema:)#i', '', trim( $type ) );
			}
		}
		return $types;
	}

	/**
	 * Definitions for an @id: nodes with that id that carry more than a reference.
	 *
	 * @param string $id Resolved id.
	 * @return array Nodes.
	 */
	public function definitions( $id ) {
		$out = array();
		if ( isset( $this->by_id[ $id ] ) ) {
			foreach ( $this->by_id[ $id ] as $key ) {
				if ( ! $this->nodes[ $key ]['is_ref'] ) {
					$out[] = $this->nodes[ $key ];
				}
			}
		}
		return $out;
	}

	/**
	 * Merged types for a node, including types declared on other nodes with the same @id.
	 *
	 * @param array $node Node.
	 * @return array
	 */
	public function all_types( array $node ) {
		$types = $node['types'];
		if ( '' !== $node['id'] ) {
			foreach ( $this->definitions( $node['id'] ) as $def ) {
				$types = array_merge( $types, $def['types'] );
			}
		}
		return array_values( array_unique( $types ) );
	}

	/**
	 * Follow a value that may be a reference to its definitions, cycle-safe.
	 *
	 * @param mixed $value   Property value.
	 * @param array $visited Ids already followed.
	 * @return array Nodes (definitions or the inline node).
	 */
	public function resolve( $value, array &$visited = array() ) {
		$out = array();
		if ( ! is_array( $value ) ) {
			return $out;
		}
		if ( self::is_list( $value ) ) {
			foreach ( $value as $item ) {
				$out = array_merge( $out, $this->resolve( $item, $visited ) );
			}
			return $out;
		}
		if ( isset( $value['@id'] ) && is_string( $value['@id'] ) ) {
			$id = $this->resolve_id( $value['@id'] );
			if ( isset( $visited[ $id ] ) ) {
				return $out;
			}
			$visited[ $id ] = true;
			$defs           = $this->definitions( $id );
			if ( ! empty( $defs ) ) {
				return $defs;
			}
		}
		$out[] = array(
			'key'       => -1,
			'id'        => isset( $value['@id'] ) && is_string( $value['@id'] ) ? $this->resolve_id( $value['@id'] ) : '',
			'types'     => self::types_of( $value ),
			'props'     => $value,
			'block'     => -1,
			'path'      => '',
			'top_level' => false,
			'is_ref'    => false,
		);
		return $out;
	}

	/**
	 * Whether an array is a JSON list.
	 *
	 * @param array $value Array.
	 * @return bool
	 */
	public static function is_list( $value ) {
		if ( ! is_array( $value ) ) {
			return false;
		}
		if ( array() === $value ) {
			return true;
		}
		return array_keys( $value ) === range( 0, count( $value ) - 1 );
	}
}
