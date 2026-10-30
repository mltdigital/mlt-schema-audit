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
	 * Whether a business or person name appears in the text or title.
	 *
	 * Case-insensitive, '&' and 'and' equivalent, whitespace-tolerant. A
	 * trailing legal suffix (LLP, Ltd, Limited, Solicitors) may be absent on
	 * the page, because pages often omit it in running text.
	 *
	 * @param string $name Name.
	 * @return bool
	 */
	public function has_name( $name ) {
		$name = trim( html_entity_decode( (string) $name, ENT_QUOTES | ENT_HTML5, 'UTF-8' ) );
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
			if ( preg_match( $pattern, $this->text ) || preg_match( $pattern, $this->title ) ) {
				return true;
			}
		}
		return false;
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

