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
		if ( get_option( 'mltsa_db_version' ) !== MLTSA_DB_VERSION ) {
			Installer::create_tables();
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
