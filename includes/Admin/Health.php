<?php
/**
 * Health checks: what would stop audits or mail, in plain English.
 * Shown on the Health screen and by `wp mltsa status`.
 *
 * @package MLT\SchemaAudit
 */

namespace MLT\SchemaAudit\Admin;

use MLT\SchemaAudit\Labels;
use MLT\SchemaAudit\Ops\Outbox;
use MLT\SchemaAudit\Ops\Scheduler;
use MLT\SchemaAudit\Settings;
use MLT\SchemaAudit\Store\Repository;

defined( 'ABSPATH' ) || exit;

/**
 * Health.
 */
class Health {

	/**
	 * Run every check.
	 *
	 * @return array List of { status: ok|warn|fail, label, detail }.
	 */
	public static function checks() {
		$repo   = new Repository();
		$s      = Settings::all();
		$out    = array();
		$add    = static function ( $status, $label, $detail ) use ( &$out ) {
			$out[] = array(
				'status' => $status,
				'label'  => $label,
				'detail' => $detail,
			);
		};
		$format = static function ( $timestamp ) {
			return $timestamp ? wp_date( 'j F Y, H:i T', (int) $timestamp ) : 'never';
		};

		if ( Settings::constant_disabled() ) {
			$add( 'fail', 'Kill switch', 'MLTSA_DISABLE is set in wp-config.php. Scheduling, mail and manual audits are all stopped.' );
		} elseif ( ! empty( $s['kill_switch'] ) ) {
			$add( 'warn', 'Kill switch', 'The kill switch setting is on. Scheduling and mail are stopped; manual audits still work.' );
		} else {
			$add( 'ok', 'Kill switch', 'Off.' );
		}

		if ( empty( $s['monitoring'] ) ) {
			$blockers = Settings::monitoring_blockers();
			$add( 'warn', 'Monthly monitoring', 'Off.' . ( empty( $blockers ) ? ' It can be switched on in Settings.' : ' Before it can be switched on: ' . implode( ' ', $blockers ) ) );
		} else {
			$next = Scheduler::next_start();
			$add( $next ? 'ok' : 'fail', 'Monthly monitoring', $next ? 'On. Next audit starts ' . $format( $next ) . '.' : 'On, but no start is scheduled. Save the settings again to rebuild it.' );
		}

		$recipients = (array) $s['recipients'];
		if ( empty( $recipients ) ) {
			$add( 'warn', 'Recipients', 'None set, so no email is sent. The site admin address is never used instead.' );
		} elseif ( Settings::mail_paused() ) {
			$add( 'fail', 'Recipients', sprintf( 'Mail is paused: the site address is now %s but the recipients were confirmed on %s. This happens after a clone, staging copy or migration. Reconfirm the recipients in Settings.', home_url( '/' ), $s['recipients_home'] ) );
		} else {
			$add( 'ok', 'Recipients', sprintf( '%d confirmed on %s.', count( $recipients ), $s['recipients_home'] ) );
		}

		$blocked = (string) get_option( 'mltsa_mail_blocked', '' );
		if ( '' !== $blocked ) {
			$add( 'warn', 'Last mail attempt', 'Held back: ' . str_replace( '_', ' ', $blocked ) . '.' );
		}
		$counts  = $repo->outbox_counts();
		$problem = ( isset( $counts['failed'] ) ? $counts['failed'] : 0 ) + ( isset( $counts['delivery_unknown'] ) ? $counts['delivery_unknown'] : 0 );
		$summary = array();
		foreach ( $counts as $state => $n ) {
			$summary[] = str_replace( '_', ' ', $state ) . ': ' . $n;
		}
		$add( $problem ? 'warn' : 'ok', 'Outbox', empty( $summary ) ? 'No notifications yet.' : implode( ', ', $summary ) . '. "Submitted" means handed to the site\'s mail system, not proof of delivery.' );

		$tick   = (int) get_option( 'mltsa_last_tick', 0 );
		$active = $repo->active_run();
		if ( defined( 'DISABLE_WP_CRON' ) && DISABLE_WP_CRON ) {
			$stale = $active && $tick < time() - 900;
			$add( $stale ? 'fail' : 'ok', 'Scheduler', 'WordPress cron is disabled, so a server cron job must run the audit (see the server cron note). Last tick: ' . $format( $tick ) . '.' . ( $stale ? ' An audit is waiting and nothing has run it for over 15 minutes.' : '' ) );
		} else {
			$add( 'ok', 'Scheduler', 'WordPress cron runs on page visits. A server cron job is still recommended. Last tick: ' . $format( $tick ) . '.' );
		}

		if ( $active ) {
			$progress = $active['progress_utc'] ? strtotime( $active['progress_utc'] . ' UTC' ) : strtotime( $active['created_utc'] . ' UTC' );
			$add( $progress < time() - 1800 ? 'warn' : 'ok', 'Audit in progress', sprintf( 'Run %d (%s): %d of %d pages, phase %s, last progress %s.', $active['id'], $active['run_type'], $active['done_count'], $active['url_count'], $active['phase'], $format( $progress ) ) );
		}
		$runs = $repo->runs( 1 );
		if ( ! empty( $runs ) && ! $active ) {
			$last = $runs[0];
			$add( in_array( $last['state'], array( 'complete' ), true ) ? 'ok' : 'warn', 'Last audit', sprintf( 'Run %d, %s: %s.', $last['id'], $format( strtotime( $last['created_utc'] . ' UTC' ) ), Labels::of( Labels::RUN_STATES, $last['state'] ) ) );
		}

		$add( function_exists( 'curl_init' ) ? 'ok' : 'fail', 'Connection pinning', function_exists( 'curl_init' ) ? 'cURL is available, so each request is pinned to the address that was checked.' : 'cURL is missing, so requests cannot be pinned and every fetch is refused.' );
		if ( defined( 'MLTSA_ALLOW_PRIVATE_SELF' ) && MLTSA_ALLOW_PRIVATE_SELF ) {
			$add( 'warn', 'Development setting', 'MLTSA_ALLOW_PRIVATE_SELF is set. Remove it on any live site.' );
		}
		$add( 'ok', 'Versions', sprintf( 'Plugin %s, rule set %s, PHP %s, WordPress %s, database schema %s.', MLTSA_VERSION, \MLT\SchemaAudit\Engine\Rules::RULESET_VERSION, PHP_VERSION, get_bloginfo( 'version' ), (string) get_option( 'mltsa_db_version' ) ) );
		return $out;
	}
}
