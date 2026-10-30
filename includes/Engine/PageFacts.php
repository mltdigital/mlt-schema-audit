<?php
/**
 * Facts published in a page's visible text, for corroborating schema values.
 *
 * Built only from text with every script block removed, plus tel: links, so
 * a value can never be corroborated by the schema that states it. Ideas
 * carried over from the legacy content corroborator: national significant
 * number comparison for phones, compact postcodes, and harvest-then-compare
 * rather than substring search over flattened text.
 *
 * @package MLT\SchemaAudit
 */

namespace MLT\SchemaAudit\Engine;

defined( 'ABSPATH' ) || defined( 'MLTSA_TESTING' ) || exit;

/**
 * PageFacts.
 */
class PageFacts {

	/**
	 * Visible text.
	 *
	 * @var string
	 */
	public $text;

	/**
	 * Visible text of the body only, without <title> or other head text.
	 *
	 * @var string
	 */
	public $body_text;

	/**
	 * Document title.
	 *
	 * @var string
	 */
	public $title;

	/**
	 * Phone numbers on the page, as national significant numbers.
	 *
	 * @var array
	 */
	public $phones;

	/**
	 * Postcodes on the page, compact upper case.
	 *
	 * @var array
	 */
	public $postcodes;

	/**
	 * Constructor.
	 *
	 * @param array $extraction Output of Extractor::extract().
	 */
	public function __construct( array $extraction ) {
		$this->text      = (string) $extraction['text'];
		$this->title     = (string) $extraction['title'];
		$this->body_text = isset( $extraction['body_text'] ) ? (string) $extraction['body_text'] : $this->text;
		$this->phones    = self::harvest_phones( $this->text, (array) $extraction['tel_links'] );
		$this->postcodes = self::harvest_postcodes( $this->text );
	}

	/**
	 * National significant number of a UK-style phone value: 01294 464341,
	 * +44 (0)1294 464341 and tel:+441294464341 all give 1294464341.
	 *
	 * @param string $value Phone.
	 * @return string '' when the value is not a plausible phone number.
	 */
	public static function phone_nsn( $value ) {
		$value  = (string) preg_replace( '/\(0\)/', '', (string) $value );
		$digits = (string) preg_replace( '/\D+/', '', $value );
		if ( 0 === strpos( $digits, '0044' ) ) {
			$digits = substr( $digits, 4 );
		} elseif ( 0 === strpos( $digits, '44' ) && strlen( $digits ) >= 11 ) {
			$digits = substr( $digits, 2 );
		}
		$digits = ltrim( $digits, '0' );
		return strlen( $digits ) >= 9 && strlen( $digits ) <= 10 ? $digits : '';
	}

	/**
	 * Compact postcode.
	 *
	 * @param string $value Postcode.
	 * @return string
	 */
	public static function postcode_compact( $value ) {
		$compact = strtoupper( (string) preg_replace( '/[^A-Za-z0-9]/', '', (string) $value ) );
		return preg_match( '/^[A-Z]{1,2}[0-9][A-Z0-9]?[0-9][A-Z]{2}$/', $compact ) ? $compact : '';
	}

	/**
	 * Every phone number in text and tel: links.
	 *
	 * @param string $text      Visible text.
	 * @param array  $tel_links Numbers from tel: links.
	 * @return array
	 */
	public static function harvest_phones( $text, array $tel_links ) {
		$found = array();
		foreach ( $tel_links as $raw ) {
			$nsn = self::phone_nsn( $raw );
			if ( '' !== $nsn ) {
				$found[ $nsn ] = true;
			}
		}
		if ( preg_match_all( '/\+?\(?\d[\d\s().\-\/]{7,}\d/', (string) $text, $m ) ) {
			foreach ( $m[0] as $raw ) {
				// A digit run can swallow the number after it ("01294 464341 51
				// High Street"), so try the run and its phone-length prefixes.
				$digits     = (string) preg_replace( '/\D+/', '', (string) preg_replace( '/\(0\)/', '', $raw ) );
				$candidates = array( $digits );
				foreach ( array( 13, 12, 11, 10 ) as $length ) {
					if ( strlen( $digits ) > $length ) {
						$candidates[] = substr( $digits, 0, $length );
					}
				}
				foreach ( $candidates as $candidate ) {
					$nsn = self::phone_nsn( $candidate );
					if ( '' !== $nsn ) {
						$found[ $nsn ] = true;
					}
				}
			}
		}
		return array_map( 'strval', array_keys( $found ) );
	}

	/**
	 * Every UK postcode in text.
	 *
	 * @param string $text Visible text.
	 * @return array
	 */
	public static function harvest_postcodes( $text ) {
		$found = array();
		if ( preg_match_all( '/\b([A-Za-z]{1,2}[0-9][A-Za-z0-9]?)\s*([0-9][A-Za-z]{2})\b/', (string) $text, $m, PREG_SET_ORDER ) ) {
			foreach ( $m as $match ) {
				$compact = self::postcode_compact( $match[1] . $match[2] );
				if ( '' !== $compact ) {
					$found[ $compact ] = true;
				}
			}
		}
		return array_map( 'strval', array_keys( $found ) );
	}

	/**
	 * Whether a phone value appears on the page.
	 *
	 * @param string $value Phone.
	 * @return bool
	 */
	public function has_phone( $value ) {
		$nsn = self::phone_nsn( $value );
		return '' !== $nsn && in_array( $nsn, $this->phones, true );
	}

	/**
	 * Whether a postcode appears on the page.
	 *
	 * @param string $value Postcode.
	 * @return bool
	 */
	public function has_postcode( $value ) {
		$compact = self::postcode_compact( $value );
		return '' !== $compact && in_array( $compact, $this->postcodes, true );
	}

	/**
	 * Words that carry no identity in a business name.
	 */
	const NAME_STOPWORDS = array( 'the', 'and', 'of', 'llp', 'ltd', 'limited', 'plc', 'solicitors', 'solicitor', 'lawyers', 'law', 'legal', 'office', 'branch', 'co', 'company', 'services', 'service' );

	/**
	 * Whether a business or person name appears in the text or title.
	 *
	 * Case-insensitive, '&' and 'and' equivalent, whitespace-tolerant. A
	 * trailing legal suffix (LLP, Ltd, Limited, Solicitors) may be absent on
	 * the page, because pages often omit it in running text. A brand written
	 * as one word in the markup ("kestrelmoray LLP") matches the same letters
	 * with spaces on the page ("Kestrel Moray LLP"). A branch name ("Firm
	 * Town") matches when every distinctive word is on the page, because
	 * branch blocks show the town as a heading next to the firm's name.
	 *
	 * @param string $name    Name.
	 * @param bool   $body    Only the body text (not the title or head).
	 * @return bool
	 */
	public function has_name( $name, $body = false ) {
		$haystacks = $body ? array( $this->body_text ) : array( $this->text, $this->title );
		$name      = trim( html_entity_decode( (string) $name, ENT_QUOTES | ENT_HTML5, 'UTF-8' ) );
		if ( '' === $name ) {
			return false;
		}
		$core = trim( (string) preg_replace( '/[\s,]+(llp|ltd\.?|limited|plc|solicitors|& co\.?|and co\.?)$/i', '', $name ) );
		foreach ( array_unique( array( $name, $core ) ) as $candidate ) {
			if ( '' === $candidate ) {
				continue;
			}
			$parts = array();
			foreach ( preg_split( '/\s+/', $candidate ) as $token ) {
				$parts[] = ( '&' === $token || 0 === strcasecmp( 'and', $token ) ) ? '(?:&|and)' : preg_quote( $token, '/' );
			}
			$pattern = '/(?<![\p{L}\p{N}])' . implode( '\s*', $parts ) . '(?![\p{L}\p{N}])/iu';
			foreach ( $haystacks as $haystack ) {
				if ( preg_match( $pattern, $haystack ) ) {
					return true;
				}
			}
			$compact = self::compact( $candidate );
			if ( strlen( $compact ) >= 6 ) {
				foreach ( $haystacks as $haystack ) {
					if ( false !== strpos( self::compact( $haystack ), $compact ) ) {
						return true;
					}
				}
			}
		}
		$words = self::significant_words( $name );
		if ( count( $words ) >= 2 ) {
			$text = strtolower( implode( ' ', $haystacks ) );
			foreach ( $words as $word ) {
				if ( ! preg_match( '/(?<![\p{L}\p{N}])' . preg_quote( $word, '/' ) . '(?![\p{L}\p{N}])/u', $text ) ) {
					return false;
				}
			}
			return true;
		}
		return false;
	}

	/**
	 * Lower case letters and digits only, '&' read as 'and'.
	 *
	 * @param string $text Text.
	 * @return string
	 */
	public static function compact( $text ) {
		$text = strtolower( str_replace( '&', 'and', (string) $text ) );
		return (string) preg_replace( '/[^\p{L}\p{N}]+/u', '', $text );
	}

	/**
	 * Distinctive words of a name: three or more letters, not a stopword.
	 *
	 * @param string $name Name.
	 * @return array
	 */
	public static function significant_words( $name ) {
		$out = array();
		foreach ( preg_split( '/[^\p{L}\p{N}]+/u', strtolower( (string) $name ) ) as $word ) {
			if ( strlen( $word ) >= 3 && ! in_array( $word, self::NAME_STOPWORDS, true ) ) {
				$out[] = $word;
			}
		}
		return array_values( array_unique( $out ) );
	}

	/**
	 * Byte offsets in the visible text where a phone number appears.
	 *
	 * @param string $value Phone.
	 * @return array
	 */
	public function phone_offsets( $value ) {
		$nsn = self::phone_nsn( $value );
		$out = array();
		if ( '' === $nsn || ! preg_match_all( '/\+?\(?\d[\d\s().\-\/]{7,}\d/', $this->text, $m, PREG_OFFSET_CAPTURE ) ) {
			return $out;
		}
		foreach ( $m[0] as $match ) {
			$digits = (string) preg_replace( '/\D+/', '', (string) preg_replace( '/\(0\)/', '', $match[0] ) );
			foreach ( array( strlen( $digits ), 13, 12, 11, 10 ) as $length ) {
				if ( strlen( $digits ) >= $length && self::phone_nsn( substr( $digits, 0, $length ) ) === $nsn ) {
					$out[] = (int) $match[1];
					break;
				}
			}
		}
		return $out;
	}

	/**
	 * Every postcode in the visible text with its byte offset.
	 *
	 * @return array List of [ compact, offset ].
	 */
	public function postcode_offsets() {
		$out = array();
		if ( preg_match_all( '/\b([A-Za-z]{1,2}[0-9][A-Za-z0-9]?)\s*([0-9][A-Za-z]{2})\b/', $this->text, $m, PREG_SET_ORDER | PREG_OFFSET_CAPTURE ) ) {
			foreach ( $m as $match ) {
				$compact = self::postcode_compact( $match[1][0] . $match[2][0] );
				if ( '' !== $compact ) {
					$out[] = array( $compact, (int) $match[0][1] );
				}
			}
		}
		return $out;
	}

	/**
	 * The postcode the page prints straight after a street line, if any.
	 *
	 * @param string $street Street address.
	 * @param int    $window Characters searched after the street.
	 * @return array Compact postcodes, one per occurrence of the street.
	 */
	public function postcodes_after_street( $street, $window = 60 ) {
		$tokens = preg_split( '/[\s,]+/', trim( html_entity_decode( (string) $street, ENT_QUOTES | ENT_HTML5, 'UTF-8' ) ) );
		$tokens = array_values( array_filter( $tokens, 'strlen' ) );
		if ( count( $tokens ) < 2 ) {
			return array();
		}
		$pattern = '/(?<![\p{L}\p{N}])' . implode( '[\s,]+', array_map( static function ( $t ) {
			return preg_quote( $t, '/' );
		}, $tokens ) ) . '(?![\p{L}\p{N}])/iu';
		$out = array();
		if ( preg_match_all( $pattern, $this->text, $m, PREG_OFFSET_CAPTURE ) ) {
			foreach ( $m[0] as $match ) {
				$after = substr( $this->text, $match[1] + strlen( $match[0] ), $window );
				if ( preg_match( '/\b([A-Za-z]{1,2}[0-9][A-Za-z0-9]?)\s*([0-9][A-Za-z]{2})\b/', $after, $pc ) ) {
					$compact = self::postcode_compact( $pc[1] . $pc[2] );
					if ( '' !== $compact ) {
						$out[] = $compact;
					}
				}
			}
		}
		return $out;
	}

	/**
	 * Whether a short phrase (FAQ question) appears in the visible text.
	 *
	 * @param string $phrase Phrase.
	 * @return bool
	 */
	public function has_phrase( $phrase ) {
		$norm = static function ( $s ) {
			$s = html_entity_decode( preg_replace( '#<[^>]*>#', ' ', (string) $s ), ENT_QUOTES | ENT_HTML5, 'UTF-8' );
			$s = str_replace( array( "\xE2\x80\x99", "\xE2\x80\x98", "\xE2\x80\x9C", "\xE2\x80\x9D" ), array( "'", "'", '"', '"' ), $s );
			return strtolower( trim( (string) preg_replace( '/[^\p{L}\p{N}]+/u', ' ', $s ) ) );
		};
		$needle = $norm( $phrase );
		return '' !== $needle && false !== strpos( ' ' . $norm( $this->text ) . ' ', ' ' . $needle . ' ' );
	}
}

