<?php
/**
 * Integration tests against the disposable WordPress in .dev/wp only.
 *
 *   PHP_CLI_SERVER_WORKERS=4 php -S 127.0.0.1:8899 -t .dev/wp
 *   wp --path=.dev/wp eval-file tests/integration/run.php
 *
 * Needs the dev mail kill switch (wp-content/mu-plugins/dev-mail-kill.php),
 * which logs every wp_mail() call to wp-content/dev-mail-log.jsonl and sends
 * nothing. Never run this against a client or pilot site. Never use
 * `wp plugin uninstall` or `wp plugin delete` here: the plugin folder is a
 * symlink to the repository, so WordPress would delete the source.
 *
 * @package MLT\SchemaAudit
 */

// phpcs:disable

use MLT\SchemaAudit\Installer;
use MLT\SchemaAudit\Ops\Calendar;
use MLT\SchemaAudit\Ops\Outbox;
use MLT\SchemaAudit\Ops\Scheduler;
use MLT\SchemaAudit\Ops\Worker;
use MLT\SchemaAudit\Settings;
use MLT\SchemaAudit\Store\Repository;

if ( ! defined( 'WP_CLI' ) || ! defined( 'MLTSA_VERSION' ) ) {
	exit( "Run with wp eval-file on the disposable site, with the plugin active.\n" );
}
if ( false === strpos( home_url(), 'localhost' ) && false === strpos( home_url(), '127.0.0.1' ) ) {
	exit( "Refusing to run: this is not the disposable local site.\n" );
}

$GLOBALS['it'] = array( 'pass' => 0, 'fail' => array(), 'asserts' => 0 );
function itest( $name, $fn ) {
	try {
		$fn();
		++$GLOBALS['it']['pass'];
		echo "ok    {$name}\n";
	} catch ( Throwable $e ) {
		$GLOBALS['it']['fail'][ $name ] = $e->getMessage() . ' (' . basename( $e->getFile() ) . ':' . $e->getLine() . ')';
		echo "FAIL  {$name}\n      " . $GLOBALS['it']['fail'][ $name ] . "\n";
	}
}
function icheck( $condition, $message ) {
	++$GLOBALS['it']['asserts'];
	if ( ! $condition ) {
		throw new RuntimeException( $message );
	}
}
function mail_log() {
	$file = WP_CONTENT_DIR . '/dev-mail-log.jsonl';
	if ( ! is_file( $file ) ) {
		return array();
	}
	return array_values( array_filter( array_map( 'json_decode', file( $file, FILE_IGNORE_NEW_LINES ) ) ) );
}
function reset_settings( array $overrides = array() ) {
	update_option( Settings::OPTION, array_merge( Settings::defaults(), array( 'gap_seconds' => 0 ), $overrides ), false );
	Settings::flush();
	wp_cache_delete( Settings::OPTION, 'options' );
}
function cron_hooks() {
	$out = array();
	foreach ( (array) _get_cron_array() as $time => $hooks ) {
		foreach ( array_keys( (array) $hooks ) as $hook ) {
			if ( 0 === strpos( $hook, 'mltsa_' ) ) {
				$out[] = $hook;
			}
		}
	}
	return $out;
}
function finish_active_runs() {
	$repo = new Repository();
	while ( $run = $repo->active_run() ) {
		$repo->update_run( (int) $run['id'], array( 'state' => 'cancelled', 'phase' => 'done', 'finished_utc' => Repository::now(), 'lock_token' => '' ) );
	}
}
function make_finished_monthly( array $summary, $state = 'complete' ) {
	$repo = new Repository();
	$id   = $repo->create_run( array( 'run_type' => 'monthly', 'trigger_type' => 'system', 'schedule_key' => 'test-' . wp_generate_password( 8, false ), 'state' => $state, 'phase' => 'done', 'url_count' => 10, 'summary' => wp_json_encode( $summary ), 'finished_utc' => Repository::now() ) );
	return $repo->get_run( $id );
}
function http( $method, $path, $cookie = '', array $post = array() ) {
	$ch = curl_init( home_url( $path ) );
	curl_setopt_array( $ch, array( CURLOPT_RETURNTRANSFER => true, CURLOPT_HEADER => true, CURLOPT_FOLLOWLOCATION => false, CURLOPT_TIMEOUT => 60 ) );
	if ( $cookie ) {
		curl_setopt( $ch, CURLOPT_HTTPHEADER, array( 'Cookie: ' . $cookie ) );
	}
	if ( 'POST' === $method ) {
		curl_setopt( $ch, CURLOPT_POST, true );
		curl_setopt( $ch, CURLOPT_POSTFIELDS, http_build_query( $post ) );
	}
	$raw    = (string) curl_exec( $ch );
	$status = (int) curl_getinfo( $ch, CURLINFO_RESPONSE_CODE );
	$size   = (int) curl_getinfo( $ch, CURLINFO_HEADER_SIZE );
	curl_close( $ch );
	return array( 'status' => $status, 'headers' => substr( $raw, 0, $size ), 'body' => substr( $raw, $size ) );
}
/**
 * Cookie for a user, and nonces valid for that cookie's session.
 */
function session_for( $user_id ) {
	if ( ! $user_id ) {
		return array( '', array() );
	}
	$expire = time() + 3600;
	$token  = WP_Session_Tokens::get_instance( $user_id )->create( $expire );
	$auth   = wp_generate_auth_cookie( $user_id, $expire, 'auth', $token );
	$logged = wp_generate_auth_cookie( $user_id, $expire, 'logged_in', $token );
	$prev   = get_current_user_id();
	$_COOKIE[ LOGGED_IN_COOKIE ] = $logged;
	wp_set_current_user( $user_id );
	$nonces = array();
	foreach ( array( 'mltsa_start', 'mltsa_settings', 'mltsa_export', 'mltsa_recheck', 'mltsa_cancel', 'mltsa_step' ) as $action ) {
		$nonces[ $action ] = wp_create_nonce( $action );
	}
	unset( $_COOKIE[ LOGGED_IN_COOKIE ] );
	wp_set_current_user( $prev );
	return array( AUTH_COOKIE . '=' . $auth . '; ' . LOGGED_IN_COOKIE . '=' . $logged, $nonces );
}
function test_user( $login, $role, $strip_caps = false ) {
	$user = get_user_by( 'login', $login );
	$id   = $user ? $user->ID : wp_insert_user( array( 'user_login' => $login, 'user_pass' => wp_generate_password( 32 ), 'role' => $role, 'user_email' => $login . '@example.invalid' ) );
	$u    = new WP_User( $id );
	$u->set_role( $role );
	if ( $strip_caps ) {
		$u->add_cap( 'mltsa_audit', false );
		$u->add_cap( 'mltsa_manage', false );
	}
	return (int) $id;
}
function snapshot() {
	global $wpdb;
	$out = array( 'tables' => array(), 'options' => array() );
	foreach ( $wpdb->get_col( "SELECT name FROM sqlite_master WHERE type = 'table'" ) as $table ) {
		if ( false !== strpos( $table, 'mltsa_' ) || 0 !== strpos( $table, $wpdb->prefix ) ) {
			continue;
		}
		if ( $wpdb->options === $table ) {
			foreach ( $wpdb->get_results( "SELECT option_name, option_value FROM {$wpdb->options}", ARRAY_A ) as $row ) {
				$out['options'][ $row['option_name'] ] = md5( $row['option_value'] );
			}
			continue;
		}
		$out['tables'][ $table ] = md5( serialize( $wpdb->get_results( "SELECT * FROM {$table}", ARRAY_N ) ) );
	}
	return $out;
}
/**
 * What changed outside the plugin's own data, ignoring core's own bookkeeping.
 */
function foreign_changes( array $a, array $b, array $also_allowed = array() ) {
	$changed = array();
	foreach ( array_unique( array_merge( array_keys( $a['tables'] ), array_keys( $b['tables'] ) ) ) as $t ) {
		if ( ( isset( $a['tables'][ $t ] ) ? $a['tables'][ $t ] : '' ) !== ( isset( $b['tables'][ $t ] ) ? $b['tables'][ $t ] : '' ) ) {
			$changed[] = 'table ' . $t;
		}
	}
	$core = array( 'cron', 'active_plugins', 'recently_activated', 'mltsa_' );
	foreach ( array_unique( array_merge( array_keys( $a['options'] ), array_keys( $b['options'] ) ) ) as $name ) {
		if ( ( isset( $a['options'][ $name ] ) ? $a['options'][ $name ] : '' ) === ( isset( $b['options'][ $name ] ) ? $b['options'][ $name ] : '' ) ) {
			continue;
		}
		$ok = false;
		foreach ( array_merge( $core, $also_allowed ) as $prefix ) {
			$ok = $ok || 0 === strpos( $name, $prefix ) || 0 === strpos( $name, '_transient_mltsa_' ) || 0 === strpos( $name, '_transient_timeout_mltsa_' ) || 0 === strpos( $name, '_transient_doing_cron' ) || 0 === strpos( $name, '_site_transient_' );
		}
		if ( ! $ok ) {
			$changed[] = 'option ' . $name;
		}
	}
	return $changed;
}

$repo  = new Repository();
$saved = get_option( Settings::OPTION );
finish_active_runs();
reset_settings();
$admin = (int) get_users( array( 'role' => 'administrator', 'number' => 1, 'fields' => 'ID' ) )[0];

/* ---------------------------------------------------------------- Stage 5 */

itest(
	'AC monitoring stays off until scope, recipients and schedule are confirmed; then exactly one start is scheduled',
	static function () use ( $admin ) {
		reset_settings();
		Settings::update( array( 'monitoring' => true ), $admin );
		icheck( ! Settings::get( 'monitoring' ), 'Refused without confirmations' );
		icheck( array() === cron_hooks() || ! in_array( 'mltsa_monthly_start', cron_hooks(), true ), 'Nothing scheduled' );
		Settings::update( array( 'recipients' => "audit@example.invalid\nsecond@example.invalid", 'scope_confirmed' => true, 'schedule_confirmed' => true, 'monitoring' => true ), $admin );
		icheck( Settings::get( 'monitoring' ), 'Switched on' );
		$starts = array_count_values( cron_hooks() );
		icheck( 1 === ( isset( $starts['mltsa_monthly_start'] ) ? $starts['mltsa_monthly_start'] : 0 ), 'Exactly one monthly start' );
		$next = Calendar::next( Settings::all(), time(), 1 );
		icheck( Scheduler::next_start() === $next[0], 'At the next occurrence' );
		icheck( 3 === count( Scheduler::next_dates() ), 'Three dates for the settings screen' );
	}
);

itest(
	'S3 deactivation leaves no mltsa_ event or lock; reactivation rebuilds the next start only, with no backlog run',
	static function () {
		$runs_before = ( new Repository() )->count_runs();
		Installer::deactivate();
		icheck( array() === cron_hooks(), 'No mltsa_ events after deactivation: ' . implode( ',', cron_hooks() ) );
		icheck( false === get_option( 'mltsa_lock_start' ), 'No start lock' );
		Installer::activate();
		$hooks = array_count_values( cron_hooks() );
		icheck( 1 === ( isset( $hooks['mltsa_monthly_start'] ) ? $hooks['mltsa_monthly_start'] : 0 ), 'One start rebuilt' );
		Scheduler::catch_up();
		icheck( ( new Repository() )->count_runs() === $runs_before, 'No catch-up or backlog run after reactivation' );
	}
);

itest(
	'AC a missed occurrence runs once as a catch-up with its lateness recorded; S2 a second start for the same month is refused',
	static function () {
		$repo = new Repository();
		finish_active_runs();
		$s        = Settings::all();
		$previous = Calendar::previous( $s, time() );
		update_option( 'mltsa_monitoring_since', $previous - 86400, false );
		$key = Calendar::schedule_key( $previous, $s['schedule_timezone'] );
		$existing = $repo->run_by_schedule_key( $key );
		if ( $existing ) {
			global $wpdb;
			$wpdb->update( $wpdb->prefix . 'mltsa_runs', array( 'schedule_key' => null ), array( 'id' => (int) $existing['id'] ) );
		}
		Scheduler::catch_up();
		$run = $repo->run_by_schedule_key( $key );
		icheck( $run && 'monthly' === $run['run_type'], 'Catch-up run created' );
		icheck( (int) $run['lateness_seconds'] > 0, 'Lateness recorded' );
		icheck( ! empty( Repository::decode( $run['scope'] )['catch_up'] ), 'Marked as catch-up' );
		$count = $repo->count_runs();
		Scheduler::catch_up();
		icheck( 0 === Scheduler::start_monthly( $previous, false ), 'Same month refused' );
		icheck( $repo->count_runs() === $count, 'No duplicate run' );
		icheck( 0 === Scheduler::start_manual( 1 ), 'A manual start is refused while the monthly run is in progress' );
		update_option( 'mltsa_monitoring_since', time(), false );
	}
);

itest(
	'S4 the kill switch setting cancels a monthly run in progress without another request; manual audits still start',
	static function () use ( $admin ) {
		$repo = new Repository();
		$run  = $repo->active_run();
		icheck( $run && 'monthly' === $run['run_type'], 'A monthly run is active' );
		Settings::update( array( 'kill_switch' => true ), $admin );
		icheck( ! in_array( 'mltsa_monthly_start', cron_hooks(), true ), 'Scheduling stopped' );
		$worker = new Worker();
		$worker->process( (int) $run['id'], 10 );
		icheck( 0 === $worker->requests, 'No request made' );
		icheck( 'cancelled' === $repo->get_run( (int) $run['id'] )['state'], 'Run cancelled' );
		$manual = Scheduler::start_manual( $admin );
		icheck( $manual > 0, 'Manual audit still available' );
		finish_active_runs();
		Settings::update( array( 'kill_switch' => false ), $admin );
		icheck( in_array( 'mltsa_monthly_start', cron_hooks(), true ), 'Rescheduled when switched off' );
	}
);

itest(
	'S4 MLTSA_DISABLE in wp-config stops manual starts, the worker and mail (separate process)',
	static function () {
		$wp  = escapeshellarg( ABSPATH );
		$cmd = 'php -d error_reporting=24575 ' . escapeshellarg( trim( (string) shell_exec( 'command -v wp' ) ) ) . ' --path=' . $wp . ' --exec=' . escapeshellarg( "define('MLTSA_DISABLE', true);" );
		$out = (string) shell_exec( $cmd . ' mltsa audit 2>&1' );
		icheck( false !== strpos( $out, 'Refused' ), 'Manual start refused: ' . trim( $out ) );
		$tick = (string) shell_exec( $cmd . ' mltsa tick --budget=5 2>&1' );
		icheck( false !== strpos( $tick, '"disabled"' ), 'Tick does nothing: ' . trim( $tick ) );
	}
);

itest(
	'M2 M4 with no recipients nothing is sent and nothing falls back to admin_email; with recipients one mail each, counts only',
	static function () use ( $admin ) {
		$repo  = new Repository();
		$mails = count( mail_log() );
		Settings::update( array( 'recipients' => '' ), $admin );
		$run = make_finished_monthly( array( 'comparison' => array( 'meaningful' => true, 'new' => 3 ), 'coverage' => array( 'ok' => 10 ), 'findings' => 3 ), 'failed' );
		icheck( 0 === Outbox::queue_for_run( $run ), 'Nothing queued' );
		Outbox::process();
		icheck( count( mail_log() ) === $mails, 'Zero wp_mail calls' );
		foreach ( mail_log() as $m ) {
			icheck( get_option( 'admin_email' ) !== $m->to, 'admin_email never used' );
		}
		Settings::update( array( 'recipients' => "audit@example.invalid\nsecond@example.invalid" ), $admin );
		update_option( 'blogname', "Evil Firm\r\nBcc: victim@example.invalid" );
		$run = make_finished_monthly( array( 'comparison' => array( 'meaningful' => true, 'new' => 3 ), 'coverage' => array( 'ok' => 10 ), 'findings' => 3 ) );
		icheck( 2 === Outbox::queue_for_run( $run ), 'Two rows queued' );
		$stats = Outbox::process();
		icheck( 2 === $stats['submitted'], 'Two submitted' );
		$log = array_slice( mail_log(), -2 );
		foreach ( $log as $m ) {
			icheck( false === strpos( $m->subject, "\n" ) && false === stripos( $m->subject, 'Evil' ), 'M1 subject from host and date only: ' . $m->subject );
			icheck( false === stripos( $m->message, 'fx-' ) && false === stripos( $m->message, 'Fixture' ) && false === stripos( $m->message, 'Evil' ), 'M2 no page URLs, titles or site name' );
			icheck( 1 === preg_match_all( '#https?://#', $m->message ), 'M2 one link only' );
			icheck( array( 'Content-Type: text/plain; charset=UTF-8' ) === (array) $m->headers, 'Fixed headers' );
		}
		update_option( 'blogname', 'MLT Schema Audit dev' );
		icheck( 0 === Outbox::queue_for_run( $run ), 'Queuing again adds nothing (one row per run, type and recipient)' );
	}
);

itest(
	'M3 when the home URL changes (clone, staging, migration) all mail pauses until recipients are reconfirmed',
	static function () use ( $admin ) {
		$clone = static function ( $url ) {
			return str_replace( array( 'localhost:8899', '127.0.0.1:8899' ), 'staging-copy.localhost:8899', $url );
		};
		add_filter( 'home_url', $clone );
		$mails = count( mail_log() );
		$run   = make_finished_monthly( array( 'comparison' => array( 'meaningful' => true ), 'coverage' => array( 'ok' => 10 ) ) );
		Outbox::queue_for_run( $run );
		$stats = Outbox::process();
		icheck( 'home_url_changed' === $stats['blocked'], 'Blocked: ' . $stats['blocked'] );
		icheck( count( mail_log() ) === $mails, 'Nothing sent from the clone' );
		$health = wp_list_pluck( MLT\SchemaAudit\Admin\Health::checks(), 'status', 'label' );
		icheck( 'fail' === $health['Recipients'], 'Health screen says why' );
		icheck( Settings::reconfirm_recipients( $admin ), 'Reconfirmed on the new address' );
		$stats = Outbox::process();
		icheck( $stats['submitted'] >= 2, 'Sends after reconfirmation' );
		remove_filter( 'home_url', $clone );
		icheck( Settings::mail_paused(), 'Back on the original address, mail pauses again' );
		Settings::reconfirm_recipients( $admin );
		icheck( ! Settings::mail_paused(), 'Reconfirmed on the original address' );
	}
);

itest(
	'M5 the plugin registers no mail filters and changes no mail settings',
	static function () {
		global $wp_filter;
		foreach ( array( 'phpmailer_init', 'wp_mail', 'wp_mail_from', 'wp_mail_from_name', 'wp_mail_content_type', 'wp_mail_charset', 'pre_wp_mail', 'wp_mail_failed', 'wp_mail_succeeded' ) as $hook ) {
			if ( empty( $wp_filter[ $hook ] ) ) {
				continue;
			}
			foreach ( $wp_filter[ $hook ]->callbacks as $callbacks ) {
				foreach ( $callbacks as $cb ) {
					$fn   = $cb['function'];
					$name = is_array( $fn ) ? ( is_object( $fn[0] ) ? get_class( $fn[0] ) : (string) $fn[0] ) : ( is_string( $fn ) ? $fn : ( $fn instanceof Closure ? ( new ReflectionFunction( $fn ) )->getFileName() : '' ) );
					icheck( false === strpos( $name, 'SchemaAudit' ) && false === strpos( $name, 'mlt-schema-audit/includes' ), "{$hook} has a plugin callback: {$name}" );
				}
			}
		}
		$src = '';
		foreach ( new RecursiveIteratorIterator( new RecursiveDirectoryIterator( MLTSA_DIR . 'includes' ) ) as $f ) {
			if ( $f->isFile() ) {
				$src .= file_get_contents( $f->getPathname() );
			}
		}
		icheck( ! preg_match( '/add_(filter|action)\(\s*[\'"](phpmailer_init|wp_mail[a-z_]*)/', $src ), 'No mail hooks in the source' );
		icheck( false === strpos( $src, "get_option( 'admin_email'" ) && false === strpos( $src, 'get_bloginfo( \'admin_email\'' ), 'admin_email never read' );
	}
);

itest(
	'M6 a send interrupted mid-way becomes delivery_unknown and is never resent; failures retry at most three times',
	static function () {
		global $wpdb;
		$repo = new Repository();
		$run  = make_finished_monthly( array( 'comparison' => array( 'meaningful' => true ), 'coverage' => array( 'ok' => 10 ) ) );
		Outbox::queue_for_run( $run );
		$rows = $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$wpdb->prefix}mltsa_outbox WHERE run_id = %d", $run['id'] ), ARRAY_A );
		// The first row was claimed by a worker that died during wp_mail().
		$wpdb->update( $wpdb->prefix . 'mltsa_outbox', array( 'state' => 'sending', 'claim_token' => 'dead', 'claimed_until' => time() - 10, 'attempts' => 1 ), array( 'id' => $rows[0]['id'] ) );
		$mails = count( mail_log() );
		Outbox::process();
		$first = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$wpdb->prefix}mltsa_outbox WHERE id = %d", $rows[0]['id'] ), ARRAY_A );
		icheck( 'delivery_unknown' === $first['state'], 'Interrupted send marked delivery_unknown: ' . $first['state'] );
		icheck( count( mail_log() ) === $mails + 1, 'Only the other recipient was sent' );
		Outbox::process();
		icheck( count( mail_log() ) === $mails + 1, 'No resend on the next tick' );

		$run2 = make_finished_monthly( array( 'comparison' => array( 'meaningful' => true ), 'coverage' => array( 'ok' => 10 ) ) );
		Outbox::queue_for_run( $run2 );
		$GLOBALS['dev_mail_fail'] = true;
		for ( $i = 0; $i < 5; $i++ ) {
			$wpdb->query( $wpdb->prepare( "UPDATE {$wpdb->prefix}mltsa_outbox SET not_before = 0 WHERE run_id = %d", $run2['id'] ) );
			Outbox::process();
		}
		unset( $GLOBALS['dev_mail_fail'] );
		$states = $wpdb->get_col( $wpdb->prepare( "SELECT CONCAT(state, ':', attempts) FROM {$wpdb->prefix}mltsa_outbox WHERE run_id = %d", $run2['id'] ) );
		icheck( array( 'failed:3', 'failed:3' ) === $states, 'Failed after three attempts: ' . implode( ',', $states ) );
	}
);

itest(
	'AC a recipient change before an unsent notification cancels and rebuilds it for the current list, logged',
	static function () use ( $admin ) {
		global $wpdb;
		Settings::update( array( 'kill_switch' => true ), $admin );
		Settings::update( array( 'kill_switch' => false ), $admin );
		$run = make_finished_monthly( array( 'comparison' => array( 'meaningful' => true ), 'coverage' => array( 'ok' => 10 ) ) );
		Outbox::queue_for_run( $run );
		Settings::update( array( 'recipients' => "audit@example.invalid\nthird@example.invalid" ), $admin );
		$rows = $wpdb->get_results( $wpdb->prepare( "SELECT recipient, state FROM {$wpdb->prefix}mltsa_outbox WHERE run_id = %d ORDER BY recipient", $run['id'] ), ARRAY_A );
		$map  = wp_list_pluck( $rows, 'state', 'recipient' );
		icheck( 'pending' === $map['audit@example.invalid'] && 'pending' === $map['third@example.invalid'] && 'cancelled' === $map['second@example.invalid'], 'Rebuilt: ' . wp_json_encode( $map ) );
		$events = ( new Repository() )->recent_events( 5, array( 'outbox_rebuilt' ) );
		icheck( ! empty( $events ), 'Rebuild logged' );
		Outbox::process();
		Settings::reconfirm_recipients( $admin );
	}
);

/* ------------------------------------------------------- Access and output */

$hostile_title = "Hostile '; DROP TABLE wp_mltsa_runs; -- <script>alert(1)</script>";
$hostile_post  = wp_insert_post( array( 'post_type' => 'page', 'post_status' => 'publish', 'post_title' => 'hostile fixture', 'post_name' => 'hostile-fixture', 'post_content' => 'x' ) );
update_post_meta( $hostile_post, '_dev_fixture', '' );
$hostile_html = '<!doctype html><html><head><title>' . esc_html( $hostile_title ) . '</title><script type="application/ld+json">' . wp_json_encode(
	array(
		'@context'  => 'https://schema.org',
		'@type'     => 'LegalService',
		'name'      => '<img src=x onerror=alert(2)>=HYPERLINK("https://evil.example")',
		'telephone' => "+44 1632 960999' OR '1'='1",
		'url'       => 'javascript:alert(3)',
		'image'     => '"><svg onload=alert(4)>',
		'description' => "Robert'); DROP TABLE wp_users;--",
	)
) . '</script></head><body><p>Nothing here matches.</p></body></html>';
set_transient( 'dev_hostile_html', $hostile_html, 3600 );
$hostile_url = get_permalink( $hostile_post );

itest(
	'A1 A5 E1 hostile titles and JSON-LD values are stored verbatim, rendered as text and neutralised in exports',
	static function () use ( $hostile_url, $admin ) {
		global $wpdb;
		finish_active_runs();
		$id = Scheduler::start_recheck( $admin, array( $hostile_url ) );
		icheck( $id > 0, 'Recheck started' );
		( new Worker() )->process( $id, 60 );
		$repo = new Repository();
		icheck( 'complete' === $repo->get_run( $id )['state'], 'Run complete: ' . $repo->get_run( $id )['state'] );
		icheck( (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->prefix}mltsa_runs" ) > 0, 'Tables intact' );
		$stored = $wpdb->get_col( $wpdb->prepare( "SELECT observed FROM {$wpdb->prefix}mltsa_occurrences WHERE run_id = %d", $id ) );
		icheck( in_array( "+44 1632 960999' OR '1'='1", $stored, true ), 'Hostile value stored verbatim' );
		list( $cookie ) = session_for( $admin );
		$page = http( 'GET', '/wp-admin/admin.php?page=mltsa-findings&run=' . $id, $cookie );
		icheck( 200 === $page['status'], 'Findings screen renders' );
		$issue_id = (int) $wpdb->get_var( $wpdb->prepare( "SELECT issue_id FROM {$wpdb->prefix}mltsa_occurrences WHERE run_id = %d AND issue_id > 0 LIMIT 1", $id ) );
		$detail = http( 'GET', '/wp-admin/admin.php?page=mltsa-findings&issue=' . $issue_id, $cookie );
		$runpg  = http( 'GET', '/wp-admin/admin.php?page=mltsa&run=' . $id, $cookie );
		foreach ( array( $page['body'], $detail['body'], $runpg['body'] ) as $html ) {
			icheck( false === strpos( $html, '<script>alert(1)' ) && false === strpos( $html, '<img src=x onerror' ) && false === strpos( $html, '<svg onload' ), 'No executable markup' );
			icheck( false === strpos( $html, 'href="javascript:alert(3)' ), 'No javascript: link' );
		}
		icheck( false !== strpos( $detail['body'] . $page['body'], '&lt;img src=x onerror' ), 'Shown as text' );
		$search = $repo->count_findings( $id, array( 'search' => "%' OR 1=1 --" ) );
		icheck( 0 === $search, 'SQL metacharacters in search match nothing' );
		$csv = ( new MLT\SchemaAudit\Export\Exporter( $repo->get_run( $id ) ) )->csv( 'findings' );
		icheck( false === strpos( $csv, ',"=HYPERLINK' ) && false === strpos( $csv, ',"<img' . "'" ) , 'No raw formula cell' );
		icheck( false !== strpos( $csv, "+44 1632 960999' OR" ) ? false !== strpos( $csv, "\"'+44 1632 960999' OR" ) : true, 'Phone starting with + neutralised' );
	}
);

itest(
	'A2 A3 A4 every screen and handler refuses anonymous users, subscribers, editors and administrators without the capability',
	static function () use ( $admin ) {
		$repo   = new Repository();
		$users  = array(
			'anonymous'      => 0,
			'subscriber'     => test_user( 'mltsa_test_subscriber', 'subscriber' ),
			'editor'         => test_user( 'mltsa_test_editor', 'editor' ),
			'admin_no_caps'  => test_user( 'mltsa_test_admin_nocap', 'administrator', true ),
		);
		$runs     = $repo->runs( 1 );
		$run_id   = (int) $runs[0]['id'];
		$settings = get_option( Settings::OPTION );
		foreach ( $users as $label => $uid ) {
			list( $cookie, $nonce ) = session_for( $uid );
			foreach ( array( 'mltsa', 'mltsa-findings', 'mltsa-settings', 'mltsa-health', 'mltsa&run=' . $run_id ) as $screen ) {
				$r = http( 'GET', '/wp-admin/admin.php?page=' . $screen, $cookie );
				icheck( in_array( $r['status'], array( 302, 403 ), true ) && false === strpos( $r['body'], 'mltsa-coverage' ), "{$label} sees {$screen}: {$r['status']}" );
			}
			$count = $repo->count_runs();
			$posts = array(
				array( 'action' => 'mltsa_start', '_wpnonce' => isset( $nonce['mltsa_start'] ) ? $nonce['mltsa_start'] : '' ),
				array( 'action' => 'mltsa_settings', '_wpnonce' => isset( $nonce['mltsa_settings'] ) ? $nonce['mltsa_settings'] : '', 'recipients' => 'attacker@example.invalid', 'kill_switch' => '1' ),
				array( 'action' => 'mltsa_cancel', '_wpnonce' => isset( $nonce['mltsa_cancel'] ) ? $nonce['mltsa_cancel'] : '' ),
				array( 'action' => 'mltsa_recheck', '_wpnonce' => isset( $nonce['mltsa_recheck'] ) ? $nonce['mltsa_recheck'] : '', 'issue_ids' => array( 1 ) ),
			);
			foreach ( $posts as $post ) {
				$r = http( 'POST', '/wp-admin/admin-post.php', $cookie, $post );
				icheck( 302 !== $r['status'] || false === strpos( $r['headers'], 'mltsa_notice' ), "{$label} {$post['action']} was handled: {$r['status']}" );
			}
			$r = http( 'GET', '/wp-admin/admin-post.php?action=mltsa_export&run=' . $run_id . '&file=zip&_wpnonce=' . ( isset( $nonce['mltsa_export'] ) ? $nonce['mltsa_export'] : '' ), $cookie );
			icheck( false === stripos( $r['headers'], 'application/zip' ) && false === strpos( $r['body'], 'PK' ), "{$label} downloaded an export" );
			$r = http( 'POST', '/wp-admin/admin-ajax.php', $cookie, array( 'action' => 'mltsa_step', 'nonce' => isset( $nonce['mltsa_step'] ) ? $nonce['mltsa_step'] : '' ) );
			icheck( false === strpos( $r['body'], '"success":true' ), "{$label} drove the worker" );
			icheck( $repo->count_runs() === $count, "{$label} started a run" );
			wp_cache_delete( Settings::OPTION, 'options' );
			icheck( get_option( Settings::OPTION ) == $settings, "{$label} changed settings" );
		}
		list( $cookie, $nonce ) = session_for( $admin );
		$r = http( 'POST', '/wp-admin/admin-post.php', $cookie, array( 'action' => 'mltsa_settings', 'recipients' => 'attacker@example.invalid' ) );
		wp_cache_delete( Settings::OPTION, 'options' );
		icheck( 403 === $r['status'] && get_option( Settings::OPTION ) == $settings, 'A3 administrator without a nonce changes nothing' );
		$r = http( 'GET', '/wp-admin/admin-post.php?action=mltsa_export&run=999999&file=zip&_wpnonce=' . $nonce['mltsa_export'], $cookie );
		icheck( 404 === $r['status'], 'A4 unknown run ID gives nothing useful: ' . $r['status'] );
		$r = http( 'GET', '/wp-admin/admin.php?page=mltsa-findings&issue=999999', $cookie );
		icheck( false !== strpos( $r['body'], 'No such finding' ), 'A4 unknown issue ID' );
		$r = http( 'GET', '/wp-admin/admin-post.php?action=mltsa_export&run=' . $run_id . '&file=zip&_wpnonce=' . $nonce['mltsa_export'], $cookie );
		icheck( false !== stripos( $r['headers'], 'application/zip' ), 'The capability holder can export' );
	}
);

itest(
	'E2 an export creates no file anywhere under wp-content',
	static function () use ( $admin ) {
		$list = static function () {
			$out = array();
			foreach ( new RecursiveIteratorIterator( new RecursiveDirectoryIterator( WP_CONTENT_DIR, FilesystemIterator::SKIP_DOTS ) ) as $f ) {
				$p = $f->getPathname();
				if ( false === strpos( $p, '/database/' ) && false === strpos( $p, 'debug.log' ) && false === strpos( $p, 'dev-mail-log' ) && false === strpos( $p, '/plugins/' ) ) {
					$out[ $p ] = $f->getMTime();
				}
			}
			return $out;
		};
		$before          = $list();
		list( $cookie, $nonce ) = session_for( $admin );
		$run             = ( new Repository() )->runs( 1 )[0];
		foreach ( array( 'zip', 'findings', 'pages', 'summary', 'changelog' ) as $file ) {
			http( 'GET', '/wp-admin/admin-post.php?action=mltsa_export&run=' . $run['id'] . '&file=' . $file . '&_wpnonce=' . $nonce['mltsa_export'], $cookie );
		}
		icheck( $list() === $before, 'No files created or changed under wp-content' );
	}
);

itest(
	'D2 the event log holds IDs, counts and codes, not page bodies, headers or evidence',
	static function () {
		global $wpdb;
		foreach ( $wpdb->get_results( "SELECT event_type, data FROM {$wpdb->prefix}mltsa_events WHERE event_type <> 'note'", ARRAY_A ) as $row ) {
			icheck( false === stripos( $row['data'], '<script' ) && false === stripos( $row['data'], 'onerror' ) && false === stripos( $row['data'], 'set-cookie' ) && strlen( $row['data'] ) < 2000, 'Event ' . $row['event_type'] . ' carries content: ' . substr( $row['data'], 0, 120 ) );
		}
	}
);

/* -------------------------------------------------------- Write boundary */

itest(
	'A6 activation, an audit, an export, a scheduled start, deactivation and uninstall change nothing outside the plugin except the two capabilities',
	static function () use ( $admin, $hostile_url ) {
		$s0 = snapshot();
		Installer::deactivate();
		$s1 = snapshot();
		icheck( array() === foreign_changes( $s0, $s1 ), 'Deactivation: ' . implode( ', ', foreign_changes( $s0, $s1 ) ) );
		Installer::activate();
		$s2 = snapshot();
		icheck( array() === foreign_changes( $s1, $s2 ), 'Activation: ' . implode( ', ', foreign_changes( $s1, $s2 ) ) );
		finish_active_runs();
		$id = Scheduler::start_recheck( $admin, array( $hostile_url, home_url( '/' ) ) );
		( new Worker() )->process( $id, 60 );
		$exporter = new MLT\SchemaAudit\Export\Exporter( ( new Repository() )->get_run( $id ) );
		$exporter->files();
		Scheduler::on_start( time() - 60 );
		finish_active_runs();
		$s3 = snapshot();
		icheck( array() === foreign_changes( $s2, $s3 ), 'Audit, export and scheduled start: ' . implode( ', ', foreign_changes( $s2, $s3 ) ) );

		update_option( Settings::OPTION, array_merge( Settings::all(), array( 'remove_data_on_uninstall' => false ) ), false );
		Installer::uninstall();
		$s4 = snapshot();
		icheck( array( 'option wp_user_roles' ) === foreign_changes( $s3, $s4 ), 'Uninstall changes only the capabilities: ' . implode( ', ', foreign_changes( $s3, $s4 ) ) );
		icheck( ! get_role( 'administrator' )->has_cap( 'mltsa_audit' ) && false === get_option( Settings::OPTION ), 'Capabilities and settings removed' );
		global $wpdb;
		icheck( (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->prefix}mltsa_runs" ) > 0, 'Audit data kept when not chosen for removal' );
		Installer::activate();
		icheck( get_role( 'administrator' )->has_cap( 'mltsa_audit' ), 'Reactivated' );
	}
);

itest(
	'AC uninstall removes the tables only when staff chose that beforehand',
	static function () {
		global $wpdb;
		$backup = $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->prefix}mltsa_runs" );
		update_option( Settings::OPTION, array_merge( Settings::defaults(), array( 'remove_data_on_uninstall' => true ) ), false );
		Installer::uninstall();
		$tables = $wpdb->get_col( "SELECT name FROM sqlite_master WHERE type = 'table' AND name LIKE '%mltsa%'" );
		icheck( array() === $tables, 'Tables removed: ' . implode( ',', $tables ) );
		Installer::activate();
		icheck( 7 === count( $wpdb->get_col( "SELECT name FROM sqlite_master WHERE type = 'table' AND name LIKE '%mltsa%'" ) ), 'Recreated on activation' );
		icheck( $backup > 0, 'There was data before' );
	}
);

if ( is_array( $saved ) ) {
	update_option( Settings::OPTION, $saved, false );
}
wp_delete_post( $hostile_post, true );
finish_active_runs();
$f = count( $GLOBALS['it']['fail'] );
printf( "\n%d passed, %d failed, %d assertions\n", $GLOBALS['it']['pass'], $f, $GLOBALS['it']['asserts'] );
if ( $f ) {
	exit( 1 );
}
