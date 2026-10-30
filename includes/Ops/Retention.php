<?php
/**
 * Retention (D1): keep at least the newest N monthly runs (Proposed 13) and
 * the newest N manual runs and rechecks; remove page evidence from older
 * runs. Never removes the run the next comparison will use as its baseline,
 * nor a run that holds the latest evidence for an issue still in play. The
 * run row itself stays as a record that the audit happened.
 *
 * @package MLT\SchemaAudit
 */

namespace MLT\SchemaAudit\Ops;

use MLT\SchemaAudit\Settings;
use MLT\SchemaAudit\Store\Repository;

defined( 'ABSPATH' ) || defined( 'MLTSA_TESTING' ) || exit;

/**
 * Retention.
 */
class Retention {

	/**
	 * Which finished runs lose their evidence.
	 *
	 * @param array $runs      Finished runs, newest first: { id, run_type, state }.
	 * @param int   $keep      Runs of each type kept.
	 * @param array $protected Run IDs never purged.
	 * @return array Run IDs.
	 */
	public static function select( array $runs, $keep, array $protected ) {
		$seen      = array();
		$purge     = array();
		$baselined = false;
		foreach ( $runs as $run ) {
			$id   = (int) $run['id'];
			$type = 'monthly' === $run['run_type'] ? 'monthly' : 'other';
			if ( 'purged' === $run['state'] ) {
				continue;
			}
			$seen[ $type ] = isset( $seen[ $type ] ) ? $seen[ $type ] + 1 : 1;
			// The newest complete or partial monthly run is the next baseline.
			if ( ! $baselined && 'monthly' === $type && in_array( $run['state'], array( 'complete', 'partial' ), true ) ) {
				$baselined = true;
				continue;
			}
			if ( $seen[ $type ] <= (int) $keep || in_array( $id, $protected, true ) ) {
				continue;
			}
			$purge[] = $id;
		}
		return $purge;
	}

	/**
	 * Apply retention.
	 *
	 * @return int Runs purged.
	 */
	public static function apply() {
		$repo  = new Repository();
		$purge = self::select( $repo->finished_runs(), (int) Settings::get( 'retention_runs' ), $repo->evidence_run_ids() );
		foreach ( $purge as $id ) {
			$repo->purge_run_evidence( $id );
		}
		if ( ! empty( $purge ) ) {
			$repo->log_event( 'retention', array( 'runs_purged' => count( $purge ) ) );
		}
		return count( $purge );
	}
}
