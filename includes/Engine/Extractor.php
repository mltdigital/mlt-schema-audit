<?php
/**
 * Read structured data and page facts out of a server HTML response.
 *
 * JSON-LD is extracted with quoted, single-quoted and unquoted type
 * attributes, any case or spacing, HTML comment or CDATA wrappers, and any
 * number of blocks. A block that fails to parse keeps its original error.
 * A block that only parses after HTML entity decoding is recorded as a parse
 * failure (that is what a consumer sees) with the decoded form kept as
 * evidence. Nothing is normalised in place and nothing is written anywhere.
 *
 * Page text for corroboration is built with every script block removed, so
 * schema can never corroborate itself.
 *
 * @package MLT\SchemaAudit
 */

namespace MLT\SchemaAudit\Engine;

defined( 'ABSPATH' ) || defined( 'MLTSA_TESTING' ) || exit;

/**
 * Extractor.
 */
class Extractor {

	/**
	 * Largest block decoded, in bytes (F4, Proposed).
	 */
	const MAX_BLOCK_BYTES = 1048576;

	/**
	 * Largest raw block stored as evidence, in bytes (Proposed).
	 */
	const MAX_STORED_BYTES = 65535;

	/**
	 * json_decode depth limit (F4, Proposed).
	 */
	const MAX_DEPTH = 64;

	/**
	 * Extract everything the rules need from one HTML document.
	 *
	 * @param string $html HTML.
	 * @return array
	 */
	public function extract( $html ) {
		$html   = (string) $html;
		$blocks = array();
		$index  = 0;

		foreach ( self::script_tags( $html ) as $tag ) {
			$attrs = self::parse_attributes( $tag['attrs'] );
			if ( ! self::is_json_ld_type( isset( $attrs['type'] ) ? $attrs['type'] : '' ) ) {
				continue;
			}
			$blocks[] = $this->read_block( $index++, $tag['content'], $attrs, $html, $tag['offset'] );
		}

		$without_scripts = self::strip_non_visible( $html );

		return array(
			'blocks'    => $blocks,
			'microdata' => (int) preg_match_all( '/<[a-z][^>]*\sitemscope(?:[\s=>\/])/i', $without_scripts ),
			'rdfa'      => (int) preg_match_all( '/<[a-z][^>]*\s(?:typeof|vocab)\s*=/i', $without_scripts ),
			'canonical' => self::find_canonical( $html ),
			'robots'    => self::find_meta( $html, 'robots' ),
			'title'     => self::find_title( $html ),
			'text'      => self::visible_text( $without_scripts ),
			'tel_links' => self::tel_links( $without_scripts ),
		);
	}

	/**
	 * Every script element, found by a linear scan rather than a regular
	 * expression, so a very large page cannot hit PCRE backtracking limits
	 * and silently lose its blocks.
	 *
	 * @param string $html HTML.
	 * @return array List of { attrs, content, offset }.
	 */
	public static function script_tags( $html ) {
		$tags   = array();
		$pos    = 0;
		$length = strlen( $html );
		while ( $pos < $length ) {
			$start = stripos( $html, '<script', $pos );
			if ( false === $start ) {
				break;
			}
			$after = isset( $html[ $start + 7 ] ) ? $html[ $start + 7 ] : '';
			if ( '' !== $after && ! ctype_space( $after ) && '>' !== $after && '/' !== $after ) {
				$pos = $start + 7;
				continue;
			}
			$open_end = strpos( $html, '>', $start );
			if ( false === $open_end ) {
				break;
			}
			$close = stripos( $html, '</script', $open_end );
			if ( false === $close ) {
				break;
			}
			$tags[] = array(
				'attrs'   => substr( $html, $start + 7, $open_end - $start - 7 ),
				'content' => substr( $html, $open_end + 1, $close - $open_end - 1 ),
				'offset'  => $start,
			);
			$close_end = strpos( $html, '>', $close );
			$pos       = false === $close_end ? $length : $close_end + 1;
		}
		return $tags;
	}

	/**
	 * Read one JSON-LD block.
	 *
	 * @param int    $index   Block position on the page.
	 * @param string $content Raw script content.
	 * @param array  $attrs   Script attributes.
	 * @param string $html    Whole document, for attribution.
	 * @param int    $offset  Byte offset of the script tag.
	 * @return array
	 */
	private function read_block( $index, $content, array $attrs, $html, $offset ) {
		$raw   = (string) $content;
		$block = array(
			'index'             => $index,
			'format'            => 'json-ld',
			'raw'               => strlen( $raw ) > self::MAX_STORED_BYTES ? substr( $raw, 0, self::MAX_STORED_BYTES ) : $raw,
			'raw_length'        => strlen( $raw ),
			'raw_truncated'     => strlen( $raw ) > self::MAX_STORED_BYTES,
			'parse'             => 'ok',
			'error'             => '',
			'entity_encoded'    => false,
			'data'              => null,
			'hash'              => hash( 'sha256', $raw ),
			'canonical_hash'    => '',
			'source'            => 'unknown',
			'source_confidence' => 'low',
		);

		list( $block['source'], $block['source_confidence'] ) = self::attribute_source( $attrs, $html, $offset );

		$json = self::unwrap( $raw );
		if ( '' === trim( $json ) ) {
			$block['parse'] = 'empty';
			$block['error'] = 'The script block is empty.';
			return $block;
		}
		if ( strlen( $json ) > self::MAX_BLOCK_BYTES ) {
			$block['parse'] = 'too_large';
			$block['error'] = sprintf( 'Block is %d bytes, over the %d byte analysis limit.', strlen( $json ), self::MAX_BLOCK_BYTES );
			return $block;
		}

		$decoded = self::decode( $json );
		if ( null !== $decoded['error'] ) {
			$block['parse'] = 'error';
			$block['error'] = $decoded['error'];
			// Entity-encoded JSON-LD: script content is raw text, so a consumer
			// reads &quot; literally and the block is invalid. Keep the
			// original failure; keep the decoded form only as evidence.
			if ( false !== strpos( $json, '&quot;' ) || false !== strpos( $json, '&#34;' ) || false !== strpos( $json, '&#x22;' ) ) {
				$retry = self::decode( html_entity_decode( $json, ENT_QUOTES | ENT_HTML5, 'UTF-8' ) );
				if ( null === $retry['error'] ) {
					$block['entity_encoded'] = true;
					$block['data']           = $retry['data'];
					$block['canonical_hash'] = hash( 'sha256', self::canonical_json( $retry['data'] ) );
				}
			}
			return $block;
		}

		$block['data']           = $decoded['data'];
		$block['canonical_hash'] = hash( 'sha256', self::canonical_json( $decoded['data'] ) );
		return $block;
	}

	/**
	 * Decode JSON with a depth limit, keeping PHP's own error text.
	 *
	 * @param string $json JSON text.
	 * @return array { data: mixed, error: string|null }
	 */
	public static function decode( $json ) {
		$json = (string) $json;
		if ( 0 === strpos( $json, "\xEF\xBB\xBF" ) ) {
			$json = substr( $json, 3 );
		}
		$data = json_decode( $json, true, self::MAX_DEPTH );
		if ( JSON_ERROR_NONE !== json_last_error() ) {
			$error = json_last_error_msg();
			if ( JSON_ERROR_DEPTH === json_last_error() ) {
				$error = sprintf( 'Nesting deeper than %d levels (%s).', self::MAX_DEPTH, $error );
			}
			return array(
				'data'  => null,
				'error' => $error,
			);
		}
		if ( ! is_array( $data ) ) {
			return array(
				'data'  => null,
				'error' => 'The block is valid JSON but not an object or array.',
			);
		}
		return array(
			'data'  => $data,
			'error' => null,
		);
	}

	/**
	 * Canonical JSON for non-destructive structural comparison: object keys
	 * sorted, array order kept (it can carry meaning), whitespace removed.
	 *
	 * @param mixed $data Decoded JSON.
	 * @return string
	 */
	public static function canonical_json( $data ) {
		return (string) json_encode( self::sort_keys( $data ), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE ); // phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- Byte-stable output is the point; wp_json_encode may alter it.
	}

	/**
	 * Recursively sort associative keys.
	 *
	 * @param mixed $data Data.
	 * @param int   $depth Current depth.
	 * @return mixed
	 */
	private static function sort_keys( $data, $depth = 0 ) {
		if ( ! is_array( $data ) || $depth > self::MAX_DEPTH ) {
			return $data;
		}
		$is_list = array_keys( $data ) === range( 0, count( $data ) - 1 );
		foreach ( $data as $key => $value ) {
			$data[ $key ] = self::sort_keys( $value, $depth + 1 );
		}
		if ( ! $is_list ) {
			ksort( $data, SORT_STRING );
		}
		return $data;
	}

	/**
	 * Strip an HTML comment or CDATA wrapper around script content.
	 *
	 * @param string $raw Raw content.
	 * @return string
	 */
	private static function unwrap( $raw ) {
		$json = trim( (string) $raw );
		if ( preg_match( '/^<!--(.*?)-->$/s', $json, $m ) ) {
			$json = trim( $m[1] );
		}
		if ( preg_match( '/^(?:\/\/\s*)?<!\[CDATA\[(.*?)(?:\/\/\s*)?\]\]>$/s', $json, $m ) ) {
			$json = trim( $m[1] );
		}
		return $json;
	}

	/**
	 * Parse tag attributes: double-quoted, single-quoted and unquoted values.
	 *
	 * @param string $attr_text Text between the tag name and '>'.
	 * @return array Lower-case names to entity-decoded values.
	 */
	public static function parse_attributes( $attr_text ) {
		$attrs = array();
		if ( preg_match_all( '/([^\s"\'>\/=]+)(?:\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([^\s"\'=<>`]+)))?/', (string) $attr_text, $m, PREG_SET_ORDER ) ) {
			foreach ( $m as $pair ) {
				$name = strtolower( $pair[1] );
				if ( isset( $attrs[ $name ] ) ) {
					continue;
				}
				$value = '';
				foreach ( array( 2, 3, 4 ) as $i ) {
					if ( isset( $pair[ $i ] ) && '' !== $pair[ $i ] ) {
						$value = $pair[ $i ];
						break;
					}
				}
				$attrs[ $name ] = html_entity_decode( $value, ENT_QUOTES | ENT_HTML5, 'UTF-8' );
			}
		}
		return $attrs;
	}

	/**
	 * Whether a type attribute names JSON-LD, ignoring case, spacing and parameters.
	 *
	 * @param string $type Type attribute value.
	 * @return bool
	 */
	public static function is_json_ld_type( $type ) {
		$type = strtolower( trim( (string) $type ) );
		$type = trim( (string) preg_replace( '/;.*$/', '', $type ) );
		$type = (string) preg_replace( '/\s+/', '', $type );
		return 'application/ld+json' === $type;
	}

	/**
	 * Which plugin or theme probably emitted a block, and how sure we are.
	 *
	 * @param array  $attrs  Script attributes.
	 * @param string $html   Document.
	 * @param int    $offset Script offset.
	 * @return array [ source, confidence ]
	 */
	private static function attribute_source( array $attrs, $html, $offset ) {
		$class = isset( $attrs['class'] ) ? strtolower( $attrs['class'] ) : '';
		$data  = isset( $attrs['data-source'] ) ? strtolower( $attrs['data-source'] ) : '';
		if ( false !== strpos( $class, 'mlt-schema-output' ) || 'mlt-schema-automation' === $data ) {
			return array( 'mlt-schema-automation', 'high' );
		}
		if ( false !== strpos( $class, 'yoast-schema-graph' ) ) {
			return array( 'yoast', 'high' );
		}
		if ( false !== strpos( $class, 'rank-math-schema' ) ) {
			return array( 'rank-math', 'high' );
		}
		if ( false !== strpos( $class, 'aioseo-schema' ) ) {
			return array( 'aioseo', 'high' );
		}
		if ( false !== strpos( $class, 'saswp-schema-markup-output' ) ) {
			return array( 'schema-and-structured-data-for-wp', 'high' );
		}
		$before = strtolower( substr( $html, max( 0, $offset - 300 ), min( 300, $offset ) ) );
		$hints  = array(
			'yoast'     => 'yoast',
			'rank math' => 'rank-math',
			'aioseo'    => 'aioseo',
			'elementor' => 'elementor',
			'propertyhive' => 'propertyhive',
		);
		foreach ( $hints as $needle => $source ) {
			if ( false !== strpos( $before, '<!-- ' . $needle ) || false !== strpos( $before, '<!--' . $needle ) || false !== strpos( $before, $needle . ' seo plugin' ) ) {
				return array( $source, 'medium' );
			}
		}
		if ( false !== strpos( $before, 'elementor-widget' ) ) {
			return array( 'elementor', 'low' );
		}
		return array( 'unknown', 'low' );
	}

	/**
	 * Remove scripts, styles, templates and noscript content.
	 *
	 * @param string $html HTML.
	 * @return string
	 */
	public static function strip_non_visible( $html ) {
		$html = (string) $html;
		$out  = '';
		$pos  = 0;
		foreach ( self::script_tags( $html ) as $tag ) {
			$out .= substr( $html, $pos, $tag['offset'] - $pos ) . ' ';
			$end  = stripos( $html, '</script', $tag['offset'] );
			$end  = false === $end ? strlen( $html ) : strpos( $html, '>', $end );
			$pos  = false === $end ? strlen( $html ) : $end + 1;
		}
		$out .= substr( $html, $pos );
		$clean = preg_replace( '#<!--.*?-->#s', ' ', $out );
		$clean = null === $clean ? $out : $clean;
		$strip = preg_replace( '#<(style|template|noscript|svg)\b[^>]*>.*?</\1\s*>#is', ' ', $clean );
		return null === $strip ? $clean : $strip;
	}

	/**
	 * Visible text: entity-decoded, tags stripped, whitespace collapsed
	 * (including non-breaking spaces).
	 *
	 * @param string $html HTML with scripts already removed.
	 * @return string
	 */
	public static function visible_text( $html ) {
		$text = (string) preg_replace( '#<(br|/p|/div|/li|/h[1-6]|/td|/tr|/span|/a)\b[^>]*>#i', '$0 ', (string) $html );
		$text = (string) preg_replace( '#<[^>]+>#', ' ', $text );
		$text = html_entity_decode( $text, ENT_QUOTES | ENT_HTML5, 'UTF-8' );
		$text = str_replace( array( "\xC2\xA0", "\xE2\x80\xAF", "\xE2\x80\x89" ), ' ', $text );
		$text = (string) preg_replace( '/\s+/u', ' ', $text );
		return trim( $text );
	}

	/**
	 * Numbers in tel: and callto: links (click-to-call numbers vanish from text).
	 *
	 * @param string $html HTML with scripts removed.
	 * @return array
	 */
	public static function tel_links( $html ) {
		$found = array();
		if ( preg_match_all( '/href\s*=\s*(?:"|\')?\s*(?:tel|callto):([^"\'\s>]+)/i', (string) $html, $m ) ) {
			foreach ( $m[1] as $raw ) {
				$found[] = rawurldecode( html_entity_decode( $raw, ENT_QUOTES | ENT_HTML5, 'UTF-8' ) );
			}
		}
		return array_values( array_unique( $found ) );
	}

	/**
	 * Canonical link href.
	 *
	 * @param string $html HTML.
	 * @return string
	 */
	public static function find_canonical( $html ) {
		if ( preg_match_all( '#<link\b([^>]*)>#i', (string) $html, $m ) ) {
			foreach ( $m[1] as $attr_text ) {
				$attrs = self::parse_attributes( $attr_text );
				if ( isset( $attrs['rel'], $attrs['href'] ) && in_array( 'canonical', preg_split( '/\s+/', strtolower( $attrs['rel'] ) ), true ) ) {
					return trim( $attrs['href'] );
				}
			}
		}
		return '';
	}

	/**
	 * A named meta tag's content.
	 *
	 * @param string $html HTML.
	 * @param string $name Meta name.
	 * @return string
	 */
	public static function find_meta( $html, $name ) {
		if ( preg_match_all( '#<meta\b([^>]*)>#i', (string) $html, $m ) ) {
			foreach ( $m[1] as $attr_text ) {
				$attrs = self::parse_attributes( $attr_text );
				if ( isset( $attrs['name'], $attrs['content'] ) && strtolower( $attrs['name'] ) === $name ) {
					return trim( $attrs['content'] );
				}
			}
		}
		return '';
	}

	/**
	 * Document title.
	 *
	 * @param string $html HTML.
	 * @return string
	 */
	public static function find_title( $html ) {
		if ( preg_match( '#<title\b[^>]*>(.*?)</title\s*>#is', (string) $html, $m ) ) {
			$title = html_entity_decode( (string) preg_replace( '#<[^>]+>#', '', $m[1] ), ENT_QUOTES | ENT_HTML5, 'UTF-8' );
			return trim( (string) preg_replace( '/\s+/u', ' ', $title ) );
		}
		return '';
	}
}
