<?php
/**
 * Admin menu, assets and request handlers.
 *
 * Every handler checks a capability and a nonce before it reads anything
 * else (A2, A3). Object IDs are looked up server-side under the same
 * capability (A4). There are no REST routes and no handlers for logged-out
 * users.
 *
 * @package MLT\SchemaAudit
 */

namespace MLT\SchemaAudit\Admin;

use MLT\SchemaAudit\Export\Exporter;
use MLT\SchemaAudit\Issues;
use MLT\SchemaAudit\Ops\Scheduler;
use MLT\SchemaAudit\Ops\Worker;
use MLT\SchemaAudit\Settings;
use MLT\SchemaAudit\Store\Repository;

defined( 'ABSPATH' ) || exit;

/**
 * Admin.
 */
class Admin {

	/**
	 * Notice codes and their messages. Only codes travel in URLs.
	 */
	const NOTICES = array(
		'started'         => array( 'success', 'Audit started.' ),
		'refused'         => array( 'error', 'The audit was not started: another audit is in progress, or MLTSA_DISABLE is set.' ),
		'recheck_started' => array( 'success', 'Recheck started for the selected pages.' ),
		'recheck_none'    => array( 'error', 'Nothing to recheck. Site-wide findings are rechecked by a full audit.' ),
		'saved'           => array( 'success', 'Saved.' ),
		'unchanged'       => array( 'info', 'Nothing changed.' ),
		'invalid'         => array( 'error', 'Not saved. See the messages below.' ),
		'cancelled'       => array( 'success', 'The audit was cancelled.' ),
	);

	/**
	 * Register hooks.
	 */
	public static function register() {
		add_action( 'admin_menu', array( __CLASS__, 'menu' ) );
		add_action( 'admin_enqueue_scripts', array( __CLASS__, 'assets' ) );
		add_action( 'admin_post_mltsa_start', array( __CLASS__, 'handle_start' ) );
		add_action( 'admin_post_mltsa_recheck', array( __CLASS__, 'handle_recheck' ) );
		add_action( 'admin_post_mltsa_issue', array( __CLASS__, 'handle_issue' ) );
		add_action( 'admin_post_mltsa_export', array( __CLASS__, 'handle_export' ) );
		add_action( 'admin_post_mltsa_settings', array( __CLASS__, 'handle_settings' ) );
		add_action( 'admin_post_mltsa_cancel', array( __CLASS__, 'handle_cancel' ) );
		add_action( 'wp_ajax_mltsa_step', array( __CLASS__, 'ajax_step' ) );
	}

	/**
	 * Menu.
	 */
	public static function menu() {
		add_menu_page( 'MLT Schema Audit', 'Schema Audit', 'mltsa_audit', 'mltsa', array( Views::class, 'audits' ), 'dashicons-search', 81 );
		add_submenu_page( 'mltsa', 'Audits', 'Audits', 'mltsa_audit', 'mltsa', array( Views::class, 'audits' ) );
		add_submenu_page( 'mltsa', 'Findings', 'Findings', 'mltsa_audit', 'mltsa-findings', array( Views::class, 'findings' ) );
		add_submenu_page( 'mltsa', 'Settings', 'Settings', 'mltsa_manage', 'mltsa-settings', array( Views::class, 'settings' ) );
		add_submenu_page( 'mltsa', 'Health', 'Health', 'mltsa_audit', 'mltsa-health', array( Views::class, 'health' ) );
	}

	/**
	 * Assets, on the plugin's own screens only.
	 *
	 * @param string $hook Screen hook.
	 */
	public static function assets( $hook ) {
		if ( false === strpos( (string) $hook, 'mltsa' ) ) {
			return;
		}
		wp_enqueue_style( 'mltsa-admin', MLTSA_URL . 'assets/admin.css', array(), MLTSA_VERSION );
		wp_enqueue_script( 'mltsa-admin', MLTSA_URL . 'assets/admin.js', array(), MLTSA_VERSION, true );
		wp_localize_script(
			'mltsa-admin',
			'mltsaAdmin',
			array(
				'ajaxUrl' => admin_url( 'admin-ajax.php' ),
				'nonce'   => wp_create_nonce( 'mltsa_step' ),
			)
		);
	}

	/**
	 * Stop unless the user holds the capability. Each handler then verifies
	 * its nonce itself, before it reads any other input.
	 *
	 * @param string $cap Capability.
	 */
	private static function require_cap( $cap ) {
		if ( ! current_user_can( $cap ) ) {
			wp_die( esc_html__( 'You do not have permission to do that.', 'mlt-schema-audit' ), '', array( 'response' => 403 ) );
		}
	}

	/**
	 * Redirect back with a notice code.
	 *
	 * @param string $page   Admin page slug.
	 * @param string $notice Notice code.
	 * @param array  $args   Extra query args (integers only).
	 */
	private static function back( $page, $notice, array $args = array() ) {
		$args = array_map( 'intval', $args );
		wp_safe_redirect(
			add_query_arg(
				array_merge(
					array(
						'page'         => $page,
						'mltsa_notice' => $notice,
					),
					$args
				),
				admin_url( 'admin.php' )
			)
		);
		exit;
	}

	/**
	 * Keep messages for the next screen (current user only, one minute).
	 *
	 * @param array $errors Messages.
	 */
	private static function keep_errors( array $errors ) {
		set_transient( 'mltsa_errors_' . get_current_user_id(), array_slice( array_map( 'strval', $errors ), 0, 10 ), 60 );
	}

	/**
	 * Messages kept for this user, removed once read.
	 *
	 * @return array
	 */
	public static function take_errors() {
		$key    = 'mltsa_errors_' . get_current_user_id();
		$errors = get_transient( $key );
		delete_transient( $key );
		return is_array( $errors ) ? $errors : array();
	}

	/**
	 * Start a manual audit.
	 */
	public static function handle_start() {
		self::require_cap( 'mltsa_audit' );
		check_admin_referer( 'mltsa_start' );
		$id = Scheduler::start_manual( get_current_user_id() );
		self::back( 'mltsa', $id ? 'started' : 'refused', $id ? array( 'run' => $id ) : array() );
	}

	/**
	 * Recheck the pages behind selected issues. URLs come from the register,
	 * never from the request.
	 */
	public static function handle_recheck() {
		self::require_cap( 'mltsa_audit' );
		check_admin_referer( 'mltsa_recheck' );
		$ids  = isset( $_POST['issue_ids'] ) ? array_map( 'absint', (array) wp_unslash( $_POST['issue_ids'] ) ) : array();
		$repo = new Repository();
		$urls = array();
		foreach ( $repo->issues_by_ids( $ids ) as $issue ) {
			if ( ! (int) $issue['site_wide'] && '' !== $issue['page_url'] ) {
				$urls[] = $issue['page_url'];
			}
		}
		if ( empty( $urls ) ) {
			self::back( 'mltsa-findings', 'recheck_none' );
		}
		$id = Scheduler::start_recheck( get_current_user_id(), $urls );
		self::back( 'mltsa', $id ? 'recheck_started' : 'refused', $id ? array( 'run' => $id ) : array() );
	}

	/**
	 * Update an issue's work status, owner, dates, link or note.
	 */
	public static function handle_issue() {
		// The ID is read first only to build the per-issue nonce action below.
		$id = isset( $_POST['issue_id'] ) ? absint( wp_unslash( $_POST['issue_id'] ) ) : 0; // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Verified on the next lines, with this ID in the action.
		self::require_cap( 'mltsa_audit' );
		check_admin_referer( 'mltsa_issue_' . $id );
		$fields  = array();
		$allowed = array( 'work_status', 'owner_user_id', 'due_date', 'external_link', 'exception_reason', 'exception_reviewer', 'exception_review_date' );
		foreach ( $allowed as $key ) {
			if ( isset( $_POST[ $key ] ) ) {
				$fields[ $key ] = 'exception_reason' === $key ? sanitize_textarea_field( wp_unslash( $_POST[ $key ] ) ) : sanitize_text_field( wp_unslash( $_POST[ $key ] ) );
			}
		}
		$note   = isset( $_POST['note'] ) ? sanitize_textarea_field( wp_unslash( $_POST['note'] ) ) : '';
		$result = Issues::update( $id, $fields, $note, get_current_user_id() );
		if ( ! empty( $result['errors'] ) ) {
			self::keep_errors( $result['errors'] );
		}
		self::back( 'mltsa-findings', ! empty( $result['errors'] ) ? 'invalid' : ( $result['saved'] ? 'saved' : 'unchanged' ), array( 'issue' => $id ) );
	}

	/**
	 * Stream an export.
	 */
	public static function handle_export() {
		self::require_cap( 'mltsa_audit' );
		check_admin_referer( 'mltsa_export' );
		$run_id = isset( $_REQUEST['run'] ) ? absint( wp_unslash( $_REQUEST['run'] ) ) : 0;
		$file   = isset( $_REQUEST['file'] ) ? sanitize_key( wp_unslash( $_REQUEST['file'] ) ) : 'zip';
		$repo   = new Repository();
		$run    = $repo->get_run( $run_id );
		if ( ! $run || in_array( $run['state'], array( 'queued', 'running', 'purged' ), true ) ) {
			wp_die( esc_html__( 'That audit cannot be exported.', 'mlt-schema-audit' ), '', array( 'response' => 404 ) );
		}
		$filter = array();
		foreach ( array( 'severity', 'rule_id', 'work_status', 'display', 'outcome' ) as $key ) {
			if ( ! empty( $_REQUEST[ $key ] ) ) {
				$filter[ $key ] = sanitize_key( wp_unslash( $_REQUEST[ $key ] ) );
			}
		}
		if ( isset( $filter['rule_id'] ) ) {
			$filter['rule_id'] = strtoupper( $filter['rule_id'] );
		}
		$exporter = new Exporter( $run, $filter );
		$repo->log_event(
			'export',
			array(
				'file'     => $file,
				'filtered' => ! empty( $filter ),
			),
			get_current_user_id(),
			'run',
			$run_id,
			$run_id
		);
		if ( in_array( $file, Exporter::FILES, true ) ) {
			$exporter->send_csv( $file );
		} else {
			$exporter->send_zip();
		}
		exit;
	}

	/**
	 * Save settings.
	 */
	public static function handle_settings() {
		self::require_cap( 'mltsa_manage' );
		check_admin_referer( 'mltsa_settings' );
		$changes = array();
		$text    = array( 'recipients', 'approved_phones', 'approved_names', 'staging_patterns' );
		$plain   = array( 'schedule_ordinal', 'schedule_weekday', 'schedule_time', 'schedule_timezone', 'max_urls', 'gap_seconds', 'timeout', 'retention_runs' );
		$bools   = array( 'monitoring', 'kill_switch', 'schedule_confirmed', 'scope_confirmed', 'sitemap_discovery', 'notify_no_change', 'remove_data_on_uninstall' );
		foreach ( $text as $key ) {
			if ( isset( $_POST[ $key ] ) ) {
				$changes[ $key ] = sanitize_textarea_field( wp_unslash( $_POST[ $key ] ) );
			}
		}
		foreach ( $plain as $key ) {
			if ( isset( $_POST[ $key ] ) ) {
				$changes[ $key ] = sanitize_text_field( wp_unslash( $_POST[ $key ] ) );
			}
		}
		foreach ( $bools as $key ) {
			$changes[ $key ] = ! empty( $_POST[ $key ] );
		}
		$changes['post_types'] = isset( $_POST['post_types'] ) ? array_map( 'sanitize_key', (array) wp_unslash( $_POST['post_types'] ) ) : array();
		$result                = Settings::update( $changes, get_current_user_id() );
		if ( empty( $result['errors'] ) && ! empty( $_POST['reconfirm_recipients'] ) ) {
			$result['saved'] = Settings::reconfirm_recipients( get_current_user_id() ) || $result['saved'];
		}
		if ( ! empty( $result['errors'] ) ) {
			self::keep_errors( $result['errors'] );
		}
		self::back( 'mltsa-settings', ! empty( $result['errors'] ) ? 'invalid' : ( $result['saved'] ? 'saved' : 'unchanged' ) );
	}

	/**
	 * Cancel the audit in progress.
	 */
	public static function handle_cancel() {
		self::require_cap( 'mltsa_manage' );
		check_admin_referer( 'mltsa_cancel' );
		$repo = new Repository();
		$run  = $repo->active_run();
		if ( $run ) {
			$repo->update_run(
				(int) $run['id'],
				array(
					'state'        => 'cancelled',
					'phase'        => 'done',
					'finished_utc' => Repository::now(),
				)
			);
			$repo->log_event( 'run_cancelled', array(), get_current_user_id(), 'run', (int) $run['id'], (int) $run['id'] );
		}
		self::back( 'mltsa', 'cancelled' );
	}

	/**
	 * Work on the audit in progress while its screen is open, so a manual
	 * audit finishes even where cron is slow. Short budget per request.
	 */
	public static function ajax_step() {
		if ( ! current_user_can( 'mltsa_audit' ) ) {
			wp_send_json_error( array( 'message' => 'forbidden' ), 403 );
		}
		check_ajax_referer( 'mltsa_step', 'nonce' );
		$repo = new Repository();
		$run  = $repo->active_run();
		if ( ! $run ) {
			wp_send_json_success( array( 'state' => 'idle' ) );
		}
		if ( Settings::constant_disabled() ) {
			wp_send_json_success( array( 'state' => 'disabled' ) );
		}
		$worker = new Worker();
		$status = $worker->process( (int) $run['id'], 8 );
		if ( ! in_array( $status['state'], array( 'queued', 'running' ), true ) ) {
			\MLT\SchemaAudit\Ops\Outbox::process();
		}
		wp_send_json_success( $status );
	}
}
