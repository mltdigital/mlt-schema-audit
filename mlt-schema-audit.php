<?php
/**
 * Plugin Name:       MLT Schema Audit
 * Description:       Read-only audit of the structured data (JSON-LD) in this site's server responses, with monthly change reports. It never creates, edits or removes schema.
 * Version:           0.1.0
 * Requires at least: 5.8
 * Requires PHP:      7.4
 * Author:            MLT Digital
 * Text Domain:       mlt-schema-audit
 * License:           Proprietary
 *
 * @package MLT\SchemaAudit
 */

defined( 'ABSPATH' ) || exit;

define( 'MLTSA_VERSION', '0.1.0' );
define( 'MLTSA_ENGINE_VERSION', '1.0.0' );
define( 'MLTSA_DB_VERSION', '1' );
define( 'MLTSA_FILE', __FILE__ );
define( 'MLTSA_DIR', plugin_dir_path( __FILE__ ) );
define( 'MLTSA_URL', plugin_dir_url( __FILE__ ) );

spl_autoload_register(
	static function ( $class_name ) {
		$prefix = 'MLT\\SchemaAudit\\';
		if ( 0 !== strpos( $class_name, $prefix ) ) {
			return;
		}
		$relative = str_replace( '\\', '/', substr( $class_name, strlen( $prefix ) ) );
		if ( preg_match( '#[^A-Za-z0-9/]#', $relative ) ) {
			return;
		}
		$file = MLTSA_DIR . 'includes/' . $relative . '.php';
		if ( is_file( $file ) ) {
			require $file;
		}
	}
);

register_activation_hook( __FILE__, array( 'MLT\\SchemaAudit\\Installer', 'activate' ) );
register_deactivation_hook( __FILE__, array( 'MLT\\SchemaAudit\\Installer', 'deactivate' ) );

add_action( 'plugins_loaded', array( 'MLT\\SchemaAudit\\Plugin', 'boot' ) );
