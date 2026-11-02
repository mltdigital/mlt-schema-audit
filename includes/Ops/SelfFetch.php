<?php
/**
 * Self-fetch stall detection. Page fetches are HTTP requests back to this
 * same site. Where PHP has very few workers (Local by Flywheel runs two),
 * the audit's own request and WordPress cron can hold all of them, so each
 * page fetch waits until its timeout. This records how page fetches went
 * in the current audit and says when that pattern shows: several fetches
 * in a row ran to the time limit while other pages of the same site
 * answered quickly.
 *
 * @package MLT\SchemaAudit
 */

namespace MLT\SchemaAudit\Ops;

defined( 'ABSPATH' ) || defined( 'MLTSA_TESTING' ) || exit;

/**
 * SelfFetch.
 */
class SelfFetch {

	/**
	 * Option holding the state for the current audit.
	 */
	const OPTION = 'mltsa_self_fetch';

	/**
	 * Fetches in a row that ran to the time limit before the warning shows.
	 */
	const SLOW_IN_ROW = 3;

	/**
	 * A page read in less than this (milliseconds) counts as quick.
	 */
	const QUICK_MS = 3000;

	/**
	 * A fetch that took at least this share of the timeout ran to the limit.
	 */
	const LIMIT_SHARE = 0.8;

	/**
	 * The state after one page fetch. Pure, so it can be tested alone.
	 *
	 * @param array $state      State so far (empty for a new audit).
	 * @param int   $run_id     Run ID.
	 * @param array $result     Fetch result (outcome, duration_ms).
	 * @param int   $timeout_s  Request timeout in use (seconds).
	 * @return array
	 */
	public static function next( array $state, $run_id, array $result, $timeout_s ) {
		if ( ! isset( $state['run_id'] ) || (int) $state['run_id'] !== (int) $run_id ) {
			$state = array(
				'run_id'   => (int) $run_id,
				'in_row'   => 0,
				'slow'     => 0,
				'quick'    => 0,
				'detected' => false,
			);
		}
		$outcome  = (string) $result['outcome'];
		$ms       = (int) $result['duration_ms'];
		$at_limit = in_array( $outcome, array( 'timeout', 'deferred' ), true ) && $ms >= (int) ( $timeout_s * 1000 * self::LIMIT_SHARE );
		if ( $at_limit ) {
			++$state['in_row'];
			++$state['slow'];
		} else {
			$state['in_row'] = 0;
			if ( 'ok' === $outcome && $ms < self::QUICK_MS ) {
				++$state['quick'];
			}
		}
		if ( $state['in_row'] >= self::SLOW_IN_ROW && $state['quick'] > 0 ) {
			$state['detected'] = true;
		}
		return $state;
	}

	/**
	 * Record one page fetch for a run.
	 *
	 * @param int   $run_id    Run ID.
	 * @param array $result    Fetch result.
	 * @param int   $timeout_s Request timeout in use (seconds).
	 */
	public static function record( $run_id, array $result, $timeout_s ) {
		$state = get_option( self::OPTION );
		$next  = self::next( is_array( $state ) ? $state : array(), $run_id, $result, $timeout_s );
		if ( $next !== $state ) {
			update_option( self::OPTION, $next, false );
		}
	}

	/**
	 * Whether the stall was seen during this run.
	 *
	 * @param int $run_id Run ID.
	 * @return bool
	 */
	public static function detected( $run_id ) {
		$state = get_option( self::OPTION );
		return is_array( $state ) && isset( $state['run_id'] ) && (int) $state['run_id'] === (int) $run_id && ! empty( $state['detected'] );
	}

	/**
	 * The message shown on the audit screen.
	 *
	 * @return string
	 */
	public static function message() {
		return __( 'This audit is slow because the site cannot answer its own requests quickly enough. Each page is read by asking this same website for it, and several requests in a row waited for the full timeout while other pages answered in under three seconds. This usually means the server has too few PHP workers (Local by Flywheel runs two), so the audit screen and WordPress cron hold them all. The audit is still working and will finish. To speed it up, raise the PHP worker limit (pm.max_children) or run audits from the server cron job (wp mltsa tick) with this screen closed.', 'mlt-schema-audit' );
	}
}
