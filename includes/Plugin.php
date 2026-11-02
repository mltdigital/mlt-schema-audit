<?php
/**
 * Runtime wiring. Registers the plugin's own cron callbacks, admin screens
 * and WP-CLI command. Registers no front-end hooks, no REST routes and no
 * mail filters (M5), and never calls, filters or unhooks the legacy plugin.
 *
 * @package MLT\SchemaAudit
 */

namespace MLT\SchemaAudit;

defined( 'ABSPATH' ) || exit;

/**
 * Plugin.
 */
class Plugin {

	/**
	 * Boot on plugins_loaded.
	 */
	public static function boot() {
		if ( get_option( 'mltsa_db_version' ) !== MLTSA_DB_VERSION && ! get_transient( 'mltsa_upgrade_retry' ) ) {
			Installer::create_tables();
			if ( get_option( 'mltsa_db_version' ) !== MLTSA_DB_VERSION ) {
				// The upgrade did not complete: try again in an hour, not on every page load.
				set_transient( 'mltsa_upgrade_retry', 1, HOUR_IN_SECONDS );
			}
		}
		Ops\Scheduler::register();
		if ( is_admin() && class_exists( Admin\Admin::class ) ) {
			Admin\Admin::register();
		}
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			\WP_CLI::add_command( 'mltsa', Cli::class );
		}
	}
}
