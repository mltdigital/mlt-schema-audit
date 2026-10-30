<?php
/**
 * Uninstall: settings and capabilities always; tables only if staff ticked
 * "remove audit data" beforehand (contract section 9).
 *
 * @package MLT\SchemaAudit
 */

defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

if ( ! defined( 'MLTSA_DIR' ) ) {
	define( 'MLTSA_DIR', plugin_dir_path( __FILE__ ) );
}
require_once MLTSA_DIR . 'includes/Installer.php';
require_once MLTSA_DIR . 'includes/Settings.php';

MLT\SchemaAudit\Installer::uninstall();
