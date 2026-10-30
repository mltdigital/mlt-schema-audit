<?php
/**
 * CSV writing for exports (contract section 7, E1).
 *
 * UTF-8 with a byte-order mark so Excel reads UK characters correctly.
 * Every cell is quoted, so leading zeros and line breaks survive in the
 * file. A cell starting with =, +, -, @, tab or carriage return is prefixed
 * with an apostrophe so a spreadsheet never evaluates it as a formula.
 * Pure PHP, so it is unit tested without WordPress.
 *
 * @package MLT\SchemaAudit
 */

namespace MLT\SchemaAudit\Export;

defined( 'ABSPATH' ) || defined( 'MLTSA_TESTING' ) || exit;

/**
 * Csv.
 */
class Csv {

	/**
	 * UTF-8 byte-order mark.
	 */
	const BOM = "\xEF\xBB\xBF";

	/**
	 * Neutralise a cell that a spreadsheet would treat as a formula.
	 *
	 * @param mixed $value Value.
	 * @return string
	 */
	public static function cell( $value ) {
		if ( null === $value ) {
			return '';
		}
		if ( is_bool( $value ) ) {
			return $value ? 'yes' : 'no';
		}
		$value = (string) $value;
		if ( '' !== $value && false !== strpos( "=+-@\t\r", $value[0] ) ) {
			$value = "'" . $value;
		}
		return $value;
	}

	/**
	 * One CSV line, every cell quoted.
	 *
	 * @param array $row Values.
	 * @return string
	 */
	public static function line( array $row ) {
		$cells = array();
		foreach ( $row as $value ) {
			$cells[] = '"' . str_replace( '"', '""', self::cell( $value ) ) . '"';
		}
		return implode( ',', $cells ) . "\r\n";
	}

	/**
	 * A whole CSV document.
	 *
	 * @param array $header Column names.
	 * @param array $rows   Rows (lists in header order).
	 * @return string
	 */
	public static function document( array $header, array $rows ) {
		$out = self::BOM . self::line( $header );
		foreach ( $rows as $row ) {
			$out .= self::line( $row );
		}
		return $out;
	}
}
