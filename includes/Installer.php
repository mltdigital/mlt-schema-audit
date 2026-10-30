<?php
/**
 * Activation, deactivation and uninstall (contract section 9).
 *
 * Activation creates tables and adds the two capabilities, and schedules
 * nothing. Deactivation clears every mltsa_* event and lock and keeps data.
 * Uninstall removes settings and capabilities, and tables only if staff
 * chose that beforehand. Nothing here touches the legacy plugin's data.
 *
 * @package MLT\SchemaAudit
 */

namespace MLT\SchemaAudit;

defined( 'ABSPATH' ) || exit;

/**
 * Installer.
 */
class Installer {

	/**
	 * Capabilities granted to administrators.
	 */
	const CAPS = array( 'mltsa_audit', 'mltsa_manage' );

	/**
	 * Every cron hook the plugin owns.
	 */
	const HOOKS = array( 'mltsa_monthly_start', 'mltsa_worker', 'mltsa_outbox', 'mltsa_retention' );

	/**
	 * Table suffixes.
	 */
	const TABLES = array( 'runs', 'run_urls', 'blocks', 'occurrences', 'issues', 'events', 'outbox' );

	/**
	 * Activate.
	 */
	public static function activate() {
		self::create_tables();
		$role = get_role( 'administrator' );
		if ( $role ) {
			foreach ( self::CAPS as $cap ) {
				$role->add_cap( $cap );
			}
		}
		if ( false === get_option( Settings::OPTION, false ) ) {
			add_option( Settings::OPTION, Settings::defaults(), '', 'no' );
		}
		Ops\Scheduler::reschedule_after_activation();
	}

	/**
	 * Deactivate: clear every hook and lock, keep data.
	 */
	public static function deactivate() {
		foreach ( self::HOOKS as $hook ) {
			wp_clear_scheduled_hook( $hook );
			wp_unschedule_hook( $hook );
		}
		delete_option( 'mltsa_lock_start' );
		// Forgetting when monitoring started means a reactivation schedules
		// the next occurrence only and never catches up a missed one.
		delete_option( 'mltsa_monitoring_since' );
	}

	/**
	 * Uninstall.
	 */
	public static function uninstall() {
		global $wpdb;
		self::deactivate();
		$settings = get_option( Settings::OPTION, array() );
		$remove   = is_array( $settings ) && ! empty( $settings['remove_data_on_uninstall'] );

		foreach ( wp_roles()->role_objects as $role ) {
			foreach ( self::CAPS as $cap ) {
				if ( $role->has_cap( $cap ) ) {
					$role->remove_cap( $cap );
				}
			}
		}
		delete_option( Settings::OPTION );
		delete_option( 'mltsa_db_version' );
		delete_option( 'mltsa_last_tick' );
		delete_option( 'mltsa_health' );
		delete_option( 'mltsa_mail_blocked' );

		if ( $remove ) {
			foreach ( self::TABLES as $table ) {
				$wpdb->query( 'DROP TABLE IF EXISTS ' . self::table( $table ) ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.DirectDatabaseQuery -- Fixed table names from a constant list.
			}
		}
	}

	/**
	 * Full table name.
	 *
	 * @param string $suffix Table suffix from TABLES.
	 * @return string
	 */
	public static function table( $suffix ) {
		global $wpdb;
		return $wpdb->prefix . 'mltsa_' . $suffix;
	}

	/**
	 * Create or upgrade tables.
	 */
	public static function create_tables() {
		global $wpdb;
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		$c = $wpdb->get_charset_collate();
		$t = array();
		foreach ( self::TABLES as $suffix ) {
			$t[ $suffix ] = self::table( $suffix );
		}

		$sql = array();

		$sql[] = "CREATE TABLE {$t['runs']} (
  id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  run_type varchar(20) NOT NULL DEFAULT 'manual',
  trigger_type varchar(20) NOT NULL DEFAULT 'user',
  trigger_user bigint(20) unsigned NOT NULL DEFAULT 0,
  schedule_key varchar(64) DEFAULT NULL,
  scope longtext NOT NULL,
  engine_version varchar(20) NOT NULL DEFAULT '',
  ruleset_version varchar(20) NOT NULL DEFAULT '',
  fingerprint longtext NOT NULL,
  state varchar(20) NOT NULL DEFAULT 'queued',
  phase varchar(20) NOT NULL DEFAULT 'discover',
  url_count int(10) unsigned NOT NULL DEFAULT 0,
  excluded_count int(10) unsigned NOT NULL DEFAULT 0,
  done_count int(10) unsigned NOT NULL DEFAULT 0,
  failed_count int(10) unsigned NOT NULL DEFAULT 0,
  baseline_run_id bigint(20) unsigned NOT NULL DEFAULT 0,
  scheduled_for_utc datetime DEFAULT NULL,
  created_utc datetime NOT NULL,
  started_utc datetime DEFAULT NULL,
  finished_utc datetime DEFAULT NULL,
  lateness_seconds int(10) unsigned NOT NULL DEFAULT 0,
  progress_utc datetime DEFAULT NULL,
  lock_token varchar(40) NOT NULL DEFAULT '',
  lock_expires int(10) unsigned NOT NULL DEFAULT 0,
  summary longtext NOT NULL,
  PRIMARY KEY  (id),
  UNIQUE KEY schedule_key (schedule_key),
  KEY state (state),
  KEY run_type (run_type, state)
) $c;";

		$sql[] = "CREATE TABLE {$t['run_urls']} (
  id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  run_id bigint(20) unsigned NOT NULL,
  seq int(10) unsigned NOT NULL DEFAULT 0,
  url varchar(2048) NOT NULL,
  url_key char(40) NOT NULL,
  discovery_source varchar(20) NOT NULL DEFAULT '',
  post_id bigint(20) unsigned NOT NULL DEFAULT 0,
  final_url varchar(2048) NOT NULL DEFAULT '',
  redirect_chain longtext NOT NULL,
  http_status smallint(5) unsigned NOT NULL DEFAULT 0,
  canonical varchar(2048) NOT NULL DEFAULT '',
  robots varchar(255) NOT NULL DEFAULT '',
  title text NOT NULL,
  fetched_utc datetime DEFAULT NULL,
  duration_ms int(10) unsigned NOT NULL DEFAULT 0,
  attempts tinyint(3) unsigned NOT NULL DEFAULT 0,
  response_hash char(64) NOT NULL DEFAULT '',
  markup_hash char(40) NOT NULL DEFAULT '',
  coverage varchar(20) NOT NULL DEFAULT 'pending',
  coverage_reason varchar(100) NOT NULL DEFAULT '',
  jsonld_count smallint(5) unsigned NOT NULL DEFAULT 0,
  microdata smallint(5) unsigned NOT NULL DEFAULT 0,
  rdfa smallint(5) unsigned NOT NULL DEFAULT 0,
  facts longtext NOT NULL,
  PRIMARY KEY  (id),
  KEY run_seq (run_id, seq),
  KEY run_coverage (run_id, coverage),
  KEY url_key (url_key)
) $c;";

		$sql[] = "CREATE TABLE {$t['blocks']} (
  id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  run_id bigint(20) unsigned NOT NULL,
  run_url_id bigint(20) unsigned NOT NULL,
  block_index smallint(5) unsigned NOT NULL DEFAULT 0,
  format varchar(20) NOT NULL DEFAULT 'json-ld',
  raw longtext NOT NULL,
  raw_length int(10) unsigned NOT NULL DEFAULT 0,
  parse_state varchar(20) NOT NULL DEFAULT '',
  parse_error text NOT NULL,
  block_hash char(64) NOT NULL DEFAULT '',
  canonical_hash char(64) NOT NULL DEFAULT '',
  source varchar(60) NOT NULL DEFAULT '',
  source_confidence varchar(10) NOT NULL DEFAULT '',
  PRIMARY KEY  (id),
  KEY run_url (run_url_id),
  KEY run_id (run_id)
) $c;";

		$sql[] = "CREATE TABLE {$t['occurrences']} (
  id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  run_id bigint(20) unsigned NOT NULL,
  run_url_id bigint(20) unsigned NOT NULL DEFAULT 0,
  issue_key char(40) NOT NULL,
  issue_id bigint(20) unsigned NOT NULL DEFAULT 0,
  rule_id varchar(20) NOT NULL,
  rule_version smallint(5) unsigned NOT NULL DEFAULT 1,
  outcome varchar(20) NOT NULL,
  severity varchar(10) NOT NULL,
  confidence varchar(10) NOT NULL,
  entity_key varchar(1024) NOT NULL DEFAULT '',
  entity_type varchar(255) NOT NULL DEFAULT '',
  property varchar(100) NOT NULL DEFAULT '',
  block_index smallint(6) NOT NULL DEFAULT -1,
  json_path varchar(1024) NOT NULL DEFAULT '',
  observed text NOT NULL,
  comparison text NOT NULL,
  snippet text NOT NULL,
  observed_hash char(40) NOT NULL DEFAULT '',
  source varchar(60) NOT NULL DEFAULT '',
  source_confidence varchar(10) NOT NULL DEFAULT '',
  site_wide tinyint(1) NOT NULL DEFAULT 0,
  PRIMARY KEY  (id),
  KEY run_issue (run_id, issue_key),
  KEY run_url (run_url_id),
  KEY issue_id (issue_id)
) $c;";

		$sql[] = "CREATE TABLE {$t['issues']} (
  id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  issue_key char(40) NOT NULL,
  page_url varchar(2048) NOT NULL DEFAULT '',
  site_wide tinyint(1) NOT NULL DEFAULT 0,
  rule_id varchar(20) NOT NULL,
  rule_version smallint(5) unsigned NOT NULL DEFAULT 1,
  severity varchar(10) NOT NULL DEFAULT '',
  entity_key varchar(1024) NOT NULL DEFAULT '',
  property varchar(100) NOT NULL DEFAULT '',
  first_run_id bigint(20) unsigned NOT NULL DEFAULT 0,
  last_run_id bigint(20) unsigned NOT NULL DEFAULT 0,
  first_observed_utc datetime DEFAULT NULL,
  last_observed_utc datetime DEFAULT NULL,
  verification_state varchar(30) NOT NULL DEFAULT 'present',
  verification_run_id bigint(20) unsigned NOT NULL DEFAULT 0,
  change_reason varchar(20) NOT NULL DEFAULT '',
  observed_hash char(40) NOT NULL DEFAULT '',
  latest_occurrence_id bigint(20) unsigned NOT NULL DEFAULT 0,
  work_status varchar(30) NOT NULL DEFAULT 'open',
  owner_user_id bigint(20) unsigned NOT NULL DEFAULT 0,
  due_date date DEFAULT NULL,
  external_link varchar(2048) NOT NULL DEFAULT '',
  exception_reason text NOT NULL,
  exception_reviewer varchar(100) NOT NULL DEFAULT '',
  exception_review_date date DEFAULT NULL,
  updated_utc datetime DEFAULT NULL,
  PRIMARY KEY  (id),
  UNIQUE KEY issue_key (issue_key),
  KEY work_status (work_status),
  KEY verification_state (verification_state),
  KEY rule_id (rule_id)
) $c;";

		$sql[] = "CREATE TABLE {$t['events']} (
  id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  created_utc datetime NOT NULL,
  actor_type varchar(10) NOT NULL DEFAULT 'system',
  actor_user_id bigint(20) unsigned NOT NULL DEFAULT 0,
  event_type varchar(40) NOT NULL,
  object_type varchar(20) NOT NULL DEFAULT '',
  object_id bigint(20) unsigned NOT NULL DEFAULT 0,
  run_id bigint(20) unsigned NOT NULL DEFAULT 0,
  data longtext NOT NULL,
  PRIMARY KEY  (id),
  KEY object (object_type, object_id),
  KEY event_type (event_type),
  KEY created (created_utc)
) $c;";

		$sql[] = "CREATE TABLE {$t['outbox']} (
  id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  run_id bigint(20) unsigned NOT NULL,
  notification_type varchar(30) NOT NULL,
  recipient varchar(254) NOT NULL,
  recipients_hash char(40) NOT NULL DEFAULT '',
  state varchar(20) NOT NULL DEFAULT 'pending',
  attempts tinyint(3) unsigned NOT NULL DEFAULT 0,
  last_error varchar(255) NOT NULL DEFAULT '',
  not_before int(10) unsigned NOT NULL DEFAULT 0,
  claim_token varchar(40) NOT NULL DEFAULT '',
  claimed_until int(10) unsigned NOT NULL DEFAULT 0,
  created_utc datetime NOT NULL,
  updated_utc datetime DEFAULT NULL,
  submitted_utc datetime DEFAULT NULL,
  PRIMARY KEY  (id),
  UNIQUE KEY one_per_recipient (run_id, notification_type, recipient),
  KEY state (state)
) $c;";

		dbDelta( $sql );
		update_option( 'mltsa_db_version', MLTSA_DB_VERSION, false );
	}
}
