<?php
/**
 * Scheduling: the monthly start event, catch-up, the worker chain and run
 * starts (contract sections 8 and 9).
 *
 * Only single events are used, so no custom cron interval is registered.
 * The monthly event carries its occurrence time; the run it starts has a
 * unique schedule key for that month, so a duplicate start is refused (S2).
 * A missed occurrence runs once as a catch-up; earlier months are never
 * replayed, because only the most recent occurrence is ever considered.
 *
 * @package MLT\SchemaAudit
 */

namespace MLT\SchemaAudit\Ops;

use MLT\SchemaAudit\Settings;
use MLT\SchemaAudit\Store\Repository;

defined( 'ABSPATH' ) || exit;

/**
 * Scheduler.
 */
class Scheduler {

	/**
	 * Monthly start hook.
	 */
	const START_HOOK = 'mltsa_monthly_start';

	/**
	 * Worker hook.
	 */
	const WORKER_HOOK = 'mltsa_worker';

	/**
	 * Outbox hook.
	 */
	const OUTBOX_HOOK = 'mltsa_outbox';

	/**
	 * Option used as a start mutex (add_option is an atomic insert).
	 */
	const START_LOCK = 'mltsa_lock_start';

	/**
	 * Register cron callbacks.
	 */
	public static function register() {
		add_action( self::START_HOOK, array( __CLASS__, 'on_start' ), 10, 1 );
		add_action( self::WORKER_HOOK, array( __CLASS__, 'on_worker' ) );
		add_action( self::OUTBOX_HOOK, array( Outbox::class, 'process' ) );
	}

	/**
	 * Activation: rebuild the next occurrence only, never a backlog (section 9).
	 */
	public static function reschedule_after_activation() {
		self::sync();
	}

	/**
	 * Make the monthly event match the settings: exactly one event at the
	 * next occurrence when monitoring is on and nothing has stopped it.
	 */
	public static function sync() {
		wp_clear_scheduled_hook( self::START_HOOK );
		wp_unschedule_hook( self::START_HOOK );
		$s = Settings::all();
		if ( empty( $s['monitoring'] ) || Settings::is_disabled() ) {
			delete_option( 'mltsa_monitoring_since' );
			return;
		}
		if ( ! get_option( 'mltsa_monitoring_since' ) ) {
			update_option( 'mltsa_monitoring_since', time(), false );
		}
		$next = Calendar::next( $s, time(), 1 );
		if ( ! empty( $next ) ) {
			wp_schedule_single_event( $next[0], self::START_HOOK, array( $next[0] ) );
		}
	}

	/**
	 * The next scheduled start, or 0.
	 *
	 * @return int
	 */
	public static function next_start() {
		$cron = _get_cron_array();
		foreach ( (array) $cron as $time => $hooks ) {
			if ( isset( $hooks[ self::START_HOOK ] ) ) {
				return (int) $time;
			}
		}
		return 0;
	}

	/**
	 * The next three dates for the settings screen.
	 *
	 * @param array|null $settings Settings, or the saved ones.
	 * @return array UTC timestamps.
	 */
	public static function next_dates( $settings = null ) {
		return Calendar::next( null === $settings ? Settings::all() : $settings, time(), 3 );
	}

	/**
	 * Monthly event fired.
	 *
	 * @param int $occurrence Occurrence the event was scheduled for.
	 */
	public static function on_start( $occurrence = 0 ) {
		if ( ! Settings::is_disabled() && Settings::get( 'monitoring' ) ) {
			$s = Settings::all();
			self::start_monthly( $occurrence ? (int) $occurrence : Calendar::previous( $s, time() ), false );
		}
		self::sync();
	}

	/**
	 * Start the run for one occurrence if none exists for it.
	 *
	 * @param int  $occurrence UTC timestamp.
	 * @param bool $catch_up   Whether this is a catch-up.
	 * @return int Run ID, or 0 if refused.
	 */
	public static function start_monthly( $occurrence, $catch_up ) {
		$s   = Settings::all();
		$key = Calendar::schedule_key( $occurrence, $s['schedule_timezone'] );
		return self::start(
			array(
				'run_type'          => 'monthly',
				'trigger_type'      => 'system',
				'schedule_key'      => $key,
				'scheduled_for_utc' => gmdate( 'Y-m-d H:i:s', (int) $occurrence ),
				'lateness_seconds'  => max( 0, time() - (int) $occurrence ),
				'scope'             => (string) wp_json_encode( self::scope_snapshot( $s, array( 'catch_up' => (bool) $catch_up ) ) ),
			),
			0
		);
	}

	/**
	 * Start a manual audit.
	 *
	 * @param int $user_id User.
	 * @return int Run ID, or 0 if refused.
	 */
	public static function start_manual( $user_id ) {
		return self::start(
			array(
				'run_type'     => 'manual',
				'trigger_type' => 'user',
				'trigger_user' => (int) $user_id,
				'scope'        => (string) wp_json_encode( self::scope_snapshot( Settings::all() ) ),
			),
			$user_id
		);
	}

	/**
	 * Start a recheck of some pages.
	 *
	 * @param int   $user_id User.
	 * @param array $urls    Page URLs from the register (never from input).
	 * @return int Run ID, or 0 if refused.
	 */
	public static function start_recheck( $user_id, array $urls ) {
		$urls = array_values( array_unique( array_filter( array_map( 'strval', $urls ) ) ) );
		if ( empty( $urls ) ) {
			return 0;
		}
		return self::start(
			array(
				'run_type'     => 'recheck',
				'trigger_type' => 'user',
				'trigger_user' => (int) $user_id,
				'scope'        => (string) wp_json_encode( self::scope_snapshot( Settings::all(), array( 'urls' => $urls ) ) ),
			),
			$user_id
		);
	}

	/**
	 * Scope snapshot stored on the run.
	 *
	 * @param array $s     Settings.
	 * @param array $extra Extra fields.
	 * @return array
	 */
	private static function scope_snapshot( array $s, array $extra = array() ) {
		return array_merge(
			array(
				'home'              => home_url( '/' ),
				'post_types'        => array_values( (array) $s['post_types'] ),
				'sitemap_discovery' => (bool) $s['sitemap_discovery'],
				'max_urls'          => (int) $s['max_urls'],
				'coverage'          => 'server-response JSON-LD audit',
			),
			$extra
		);
	}

	/**
	 * Create a run if no other run is in progress (S2). The constant stops
	 * every start, manual included.
	 *
	 * @param array $fields  Run fields.
	 * @param int   $user_id User.
	 * @return int
	 */
	private static function start( array $fields, $user_id ) {
		if ( Settings::constant_disabled() ) {
			return 0;
		}
		if ( ! add_option( self::START_LOCK, time(), '', 'no' ) ) {
			$held = (int) get_option( self::START_LOCK );
			if ( $held > time() - 60 ) {
				return 0;
			}
			delete_option( self::START_LOCK );
			if ( ! add_option( self::START_LOCK, time(), '', 'no' ) ) {
				return 0;
			}
		}
		try {
			$repo = new Repository();
			if ( $repo->active_run() ) {
				return 0;
			}
			$id = $repo->create_run( $fields );
			if ( $id ) {
				$repo->log_event( 'run_started', array( 'type' => $fields['run_type'] ), (int) $user_id, 'run', $id, $id );
				self::kick_worker( 0 );
			}
			return $id;
		} finally {
			delete_option( self::START_LOCK );
		}
	}

	/**
	 * Start a monthly run for the most recent occurrence if it was missed.
	 */
	public static function catch_up() {
		$s = Settings::all();
		if ( empty( $s['monitoring'] ) || Settings::is_disabled() ) {
			return;
		}
		$previous = Calendar::previous( $s, time() );
		$since    = (int) get_option( 'mltsa_monitoring_since' );
		if ( ! $previous || $previous <= $since ) {
			return;
		}
		$repo = new Repository();
		if ( $repo->run_by_schedule_key( Calendar::schedule_key( $previous, $s['schedule_timezone'] ) ) ) {
			return;
		}
		self::start_monthly( $previous, true );
	}

	/**
	 * Make sure a worker event is queued.
	 *
	 * @param int $delay Seconds from now.
	 */
	public static function kick_worker( $delay = 0 ) {
		if ( ! wp_next_scheduled( self::WORKER_HOOK ) ) {
			wp_schedule_single_event( time() + (int) $delay, self::WORKER_HOOK );
		}
	}

	/**
	 * Worker event fired by WordPress cron: a short budget, well inside the
	 * PHP time limit of a web request.
	 */
	public static function on_worker() {
		$limit  = (int) ini_get( 'max_execution_time' );
		$budget = $limit > 0 ? max( 5, min( 20, $limit - 10 ) ) : 20;
		Worker::tick( $budget );
	}
}
