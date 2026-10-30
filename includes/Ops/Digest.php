<?php
/**
 * The monthly email: subject and body (contract section 8, M1, M2).
 *
 * The subject is built from the site host and the run date only, with every
 * control character removed. The body carries the host, the run date, counts
 * and an authenticated link. Never page titles, page URLs, evidence, notes
 * or personal data. Pure PHP, so it is unit tested without WordPress.
 *
 * @package MLT\SchemaAudit
 */

namespace MLT\SchemaAudit\Ops;

defined( 'ABSPATH' ) || defined( 'MLTSA_TESTING' ) || exit;

/**
 * Digest.
 */
class Digest {

	/**
	 * Notification types.
	 */
	const TYPES = array( 'changes', 'baseline', 'alert', 'no_change' );

	/**
	 * Strip anything that could break a header line.
	 *
	 * @param string $text Text.
	 * @return string
	 */
	public static function header_safe( $text ) {
		return trim( (string) preg_replace( '/[\x00-\x1F\x7F]+/', ' ', (string) $text ) );
	}

	/**
	 * Subject line.
	 *
	 * @param string $host Site host.
	 * @param string $date Run date (Y-m-d).
	 * @param string $type Notification type.
	 * @return string
	 */
	public static function subject( $host, $date, $type ) {
		$labels = array(
			'changes'   => 'changes found',
			'baseline'  => 'first audit complete',
			'alert'     => 'operational alert',
			'no_change' => 'no changes',
		);
		$label = isset( $labels[ $type ] ) ? $labels[ $type ] : 'report';
		$host  = preg_replace( '/[^a-z0-9.\-:]/i', '', (string) $host );
		$date  = preg_replace( '/[^0-9\-]/', '', (string) $date );
		return self::header_safe( sprintf( 'Schema audit for %s, %s: %s', $host, $date, $label ) );
	}

	/**
	 * Which notification a finished run needs, or '' for none.
	 *
	 * @param array $run              Run row.
	 * @param array $summary          Decoded summary.
	 * @param bool  $notify_no_change Whether no-change confirmations are on.
	 * @return string
	 */
	public static function type_for( array $run, array $summary, $notify_no_change ) {
		if ( in_array( $run['state'], array( 'partial', 'failed', 'cancelled' ), true ) ) {
			return 'alert';
		}
		if ( ! empty( $summary['is_baseline'] ) ) {
			return 'baseline';
		}
		if ( ! empty( $summary['comparison']['meaningful'] ) ) {
			return 'changes';
		}
		return $notify_no_change ? 'no_change' : '';
	}

	/**
	 * Plain-text body: counts and a link only.
	 *
	 * @param array $d { host, date, type, state, pages_read, pages_total, pages_unavailable,
	 *                 findings, comparison (counts), link }.
	 * @return string
	 */
	public static function body( array $d ) {
		$c     = isset( $d['comparison'] ) && is_array( $d['comparison'] ) ? $d['comparison'] : array();
		$n     = static function ( $key ) use ( $c ) {
			return isset( $c[ $key ] ) ? (int) $c[ $key ] : 0;
		};
		$lines = array();

		if ( 'alert' === $d['type'] ) {
			$lines[] = 'This is an operational alert, not an all-clear. The audit did not read every page.';
			$lines[] = '';
		}
		$lines[] = sprintf( 'Site: %s', self::header_safe( $d['host'] ) );
		$lines[] = sprintf( 'Audit date: %s', self::header_safe( $d['date'] ) );
		$lines[] = sprintf( 'Run state: %s', self::header_safe( $d['state'] ) );
		$lines[] = sprintf( 'Pages read: %d of %d', (int) $d['pages_read'], (int) $d['pages_total'] );
		if ( (int) $d['pages_unavailable'] > 0 ) {
			$lines[] = sprintf( 'Pages not read (timeout, blocked or error): %d', (int) $d['pages_unavailable'] );
		}
		$lines[] = sprintf( 'Findings in this run: %d', (int) $d['findings'] );
		$lines[] = '';
		if ( 'baseline' === $d['type'] ) {
			$lines[] = 'This is the first audit, so it becomes the baseline. Later audits are compared with it.';
		} elseif ( ! empty( $c ) ) {
			$lines[] = 'Compared with the previous audit:';
			$lines[] = sprintf( '  New findings: %d', $n( 'new' ) );
			$lines[] = sprintf( '  New because a rule changed (not a website change): %d', $n( 'new_rule_change' ) );
			$lines[] = sprintf( '  Returned: %d', $n( 'returned' ) );
			$lines[] = sprintf( '  Changed: %d', $n( 'changed' ) );
			$lines[] = sprintf( '  No longer detected: %d', $n( 'resolved' ) );
			$lines[] = sprintf( '  Pages with changed markup: %d', $n( 'markup_changed' ) );
			$lines[] = sprintf( '  Pages added: %d, removed: %d', $n( 'pages_added' ), $n( 'pages_removed' ) );
			$lines[] = sprintf( '  Pages read last time but not this time: %d', $n( 'coverage_lost' ) );
		} elseif ( 'no_change' === $d['type'] ) {
			$lines[] = 'Nothing changed since the previous audit.';
		}
		$lines[] = '';
		$lines[] = 'Open the full report (WordPress login required):';
		$lines[] = (string) $d['link'];
		$lines[] = '';
		$lines[] = 'Coverage: server-response JSON-LD audit. Markup added by JavaScript after the page loads is not seen.';
		$lines[] = '"Submitted" in the audit log means the site handed this email to its mail system; it does not prove delivery.';
		return implode( "\n", $lines ) . "\n";
	}

	/**
	 * Fixed headers. Nothing from settings or content goes here.
	 *
	 * @return array
	 */
	public static function headers() {
		return array( 'Content-Type: text/plain; charset=UTF-8' );
	}
}
