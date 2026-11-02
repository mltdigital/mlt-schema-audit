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

use MLT\SchemaAudit\Engine\Evaluator;
use MLT\SchemaAudit\Engine\Rules;
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
	// MLTSA_ITEST=<text> runs only the tests whose name contains it.
	$only = (string) getenv( 'MLTSA_ITEST' );
	if ( '' !== $only && false === stripos( $name, $only ) ) {
		return;
	}
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
	Scheduler::sync();
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

if ( getenv( 'MLTSA_IT_FULL' ) ) {
	itest(
		'AC hard gate: a full audit of 500 or more URLs completes, one request at a time, with every page read',
		static function () use ( $admin ) {
			finish_active_runs();
			$id = Scheduler::start_manual( $admin );
			icheck( $id > 0, 'Started' );
			$worker  = new Worker();
			$started = microtime( true );
			do {
				$status = $worker->process( $id, 120 );
			} while ( in_array( $status['state'], array( 'queued', 'running' ), true ) && microtime( true ) - $started < 900 );
			$run = ( new Repository() )->get_run( $id );
			icheck( 'complete' === $run['state'], 'Complete: ' . $run['state'] );
			icheck( (int) $run['url_count'] >= 500, 'At least 500 URLs: ' . $run['url_count'] );
			$coverage = Repository::decode( $run['summary'] )['coverage'];
			icheck( (int) $coverage['ok'] === (int) $run['url_count'], 'Every page read: ' . wp_json_encode( $coverage ) );
			echo '      ' . (int) $run['url_count'] . ' URLs in ' . round( microtime( true ) - $started ) . " s\n";
		}
	);
}

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
	'Finding 5 the outbox queues its own event at the earliest retry, due rows are not crowded out, and a block queues nothing until lifted',
	static function () use ( $admin ) {
		global $wpdb;
		$table = $wpdb->prefix . 'mltsa_outbox';
		$wpdb->query( "UPDATE {$table} SET state = 'cancelled', last_error = 'test_isolation' WHERE state IN ('pending', 'sending')" );
		wp_clear_scheduled_hook( Scheduler::OUTBOX_HOOK );
		icheck( null === Outbox::schedule_next() && false === wp_next_scheduled( Scheduler::OUTBOX_HOOK ), 'Nothing pending, no outbox event' );

		// Both sends fail: the retry is five minutes out and the event follows it.
		$run = make_finished_monthly( array( 'comparison' => array( 'meaningful' => true ), 'coverage' => array( 'ok' => 10 ) ) );
		Outbox::queue_for_run( $run );
		icheck( wp_next_scheduled( Scheduler::OUTBOX_HOOK ) <= time(), 'Queuing schedules an immediate send' );
		wp_clear_scheduled_hook( Scheduler::OUTBOX_HOOK ); // As wp-cron does before it runs the event.
		$before                   = time();
		$GLOBALS['dev_mail_fail'] = true;
		Outbox::process();
		unset( $GLOBALS['dev_mail_fail'] );
		$retry = (int) $wpdb->get_var( $wpdb->prepare( "SELECT MIN(not_before) FROM {$table} WHERE run_id = %d AND state = 'pending'", $run['id'] ) );
		icheck( $retry >= $before + 300, 'Retry set five minutes out' );
		icheck( wp_next_scheduled( Scheduler::OUTBOX_HOOK ) === $retry, 'Outbox event at the earliest retry: ' . wp_next_scheduled( Scheduler::OUTBOX_HOOK ) . ' vs ' . $retry );

		// Rows waiting for a retry have lower IDs; a due row still goes first.
		$run2 = make_finished_monthly( array( 'comparison' => array( 'meaningful' => true ), 'coverage' => array( 'ok' => 10 ) ) );
		Outbox::queue_for_run( $run2 );
		wp_clear_scheduled_hook( Scheduler::OUTBOX_HOOK );
		$mails = count( mail_log() );
		$stats = Outbox::process( 1 );
		icheck( 1 === $stats['submitted'] && count( mail_log() ) === $mails + 1, 'Due row sent with limit 1: ' . wp_json_encode( $stats ) );
		icheck( wp_next_scheduled( Scheduler::OUTBOX_HOOK ) <= time(), 'Another due row: event queued for now' );

		// Kill switch: no event while blocked; lifting it queues one.
		Settings::update( array( 'kill_switch' => true ), $admin );
		wp_clear_scheduled_hook( Scheduler::OUTBOX_HOOK );
		$stats = Outbox::process();
		icheck( 'kill_switch' === $stats['blocked'] && false === wp_next_scheduled( Scheduler::OUTBOX_HOOK ), 'Blocked: no event queued' );
		Settings::update( array( 'kill_switch' => false ), $admin );
		icheck( wp_next_scheduled( Scheduler::OUTBOX_HOOK ) <= time(), 'Lifting the kill switch queues an event' );
		wp_clear_scheduled_hook( Scheduler::OUTBOX_HOOK );
		$stats = Outbox::process();
		icheck( 1 === $stats['submitted'], 'Waiting row sent once unblocked' );

		// A lost event is put back by the hourly watchdog.
		wp_clear_scheduled_hook( Scheduler::OUTBOX_HOOK );
		Scheduler::on_watchdog();
		icheck( wp_next_scheduled( Scheduler::OUTBOX_HOOK ) === $retry, 'Watchdog requeues the outbox event at the retry' );

		$wpdb->query( $wpdb->prepare( "UPDATE {$table} SET state = 'cancelled', last_error = 'test_cleanup' WHERE run_id = %d AND state = 'pending'", $run['id'] ) );
		wp_clear_scheduled_hook( Scheduler::OUTBOX_HOOK );
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
	'Review 10 a searched export holds the findings the screen shows, and says it is filtered',
	static function () use ( $hostile_url, $admin ) {
		finish_active_runs();
		$id = Scheduler::start_recheck( $admin, array( $hostile_url ) );
		( new Worker() )->process( $id, 60 );
		$repo = new Repository();
		icheck( 'complete' === $repo->get_run( $id )['state'], 'Run complete' );
		$all = $repo->findings( $id, array(), 0 );
		icheck( count( $all ) >= 2, 'The run has findings to filter' );
		$term = '960999';
		$want = array();
		foreach ( $repo->findings( $id, array( 'search' => $term ), 0 ) as $f ) {
			$want[] = (int) $f['id'];
		}
		icheck( ! empty( $want ) && count( $want ) < count( $all ), 'The search matches some findings, not all' );

		list( $cookie, $nonce ) = session_for( $admin );
		$ids = static function ( $csv ) {
			$rows = array_map( 'str_getcsv', preg_split( '/\r?\n/', trim( preg_replace( '/^\xEF\xBB\xBF/', '', $csv ) ) ) );
			array_shift( $rows );
			return array_map( 'intval', array_column( $rows, 0 ) );
		};
		$url = '/wp-admin/admin-post.php?action=mltsa_export&run=' . $id . '&_wpnonce=' . $nonce['mltsa_export'];

		$r = http( 'GET', $url . '&file=findings&search=' . rawurlencode( $term ), $cookie );
		$got = $ids( $r['body'] );
		sort( $got );
		sort( $want );
		icheck( $got === $want, 'Exported finding IDs match the search: ' . implode( ',', $got ) . ' vs ' . implode( ',', $want ) );

		$r = http( 'GET', $url . '&file=summary&search=' . rawurlencode( $term ), $cookie );
		icheck( false !== strpos( $r['body'], 'Filtered' ) && false !== strpos( $r['body'], $term ), 'Search alone is labelled a filtered export' );

		$r = http( 'GET', $url . '&file=findings', $cookie );
		icheck( count( $ids( $r['body'] ) ) === count( $all ), 'Without a search the export is full' );

		// Tags are stripped as on the screen, and a search of "0" is a search.
		$r = http( 'GET', $url . '&file=summary&search=' . rawurlencode( '<b>' . $term . '</b>' ), $cookie );
		icheck( false === strpos( $r['body'], '<b>' ), 'Search is sanitised like the screen' );
		$r = http( 'GET', $url . '&file=summary&search=0', $cookie );
		icheck( false !== strpos( $r['body'], 'Filtered' ), 'A search for 0 is kept' );

		// The screen's download link carries the search.
		$page = http( 'GET', '/wp-admin/admin.php?page=mltsa-findings&run=' . $id . '&s=' . rawurlencode( $term ), $cookie );
		icheck( false !== strpos( $page['body'], 'filtered view' ) && 1 === preg_match( '/mltsa_export[^"]*search=' . $term . '/', $page['body'] ), 'The ZIP link on the filtered screen carries the search' );
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
			foreach ( array( 'mltsa', 'mltsa-findings', 'mltsa-register', 'mltsa-settings', 'mltsa-health', 'mltsa&run=' . $run_id ) as $screen ) {
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

/**
 * Transport that times out every request, for the budget tests.
 */
function timing_out_client() {
	return new class() implements MLT\SchemaAudit\Engine\HttpClient {
		public $count    = 0;
		public $timeouts = array();
		public function request( $url, $pinned_ip, array $args ) {
			++$this->count;
			$this->timeouts[] = (int) $args['timeout'];
			return array( 'status' => 0, 'error_code' => 'timeout', 'error' => 'timed out', 'headers' => array(), 'body' => '', 'truncated' => false, 'pinned' => true );
		}
	};
}

itest(
	'Branch review R1: with the audit screen\'s 8 second budget, a page that needs 10 seconds is read with the full timeout',
	static function () use ( $admin ) {
		finish_active_runs();
		reset_settings( array( 'timeout' => 15 ) );
		$repo   = new Repository();
		$id     = Scheduler::start_recheck( $admin, array( home_url( '/' ) ) );
		$client = new class() implements MLT\SchemaAudit\Engine\HttpClient {
			public $timeouts = array();
			public function request( $url, $pinned_ip, array $args ) {
				$this->timeouts[] = (int) $args['timeout'];
				if ( $args['timeout'] < 10 ) {
					return array( 'status' => 0, 'error_code' => 'timeout', 'error' => 'timed out', 'headers' => array(), 'body' => '', 'truncated' => false, 'pinned' => true );
				}
				return array( 'status' => 200, 'error_code' => '', 'error' => '', 'headers' => array( 'content-type' => 'text/html' ), 'body' => '<html><head><title>Slow</title></head><body></body></html>', 'truncated' => false, 'pinned' => true );
			}
		};
		icheck( $id > 0, 'Recheck started' );
		// The audit screen's AJAX step calls process() with 8 seconds.
		( new Worker( $client, static function () {} ) )->process( $id, 8 );
		icheck( array( 15 ) === $client->timeouts, 'One request, sent the full timeout: ' . wp_json_encode( $client->timeouts ) );
		global $wpdb;
		$url = $wpdb->get_row( $wpdb->prepare( 'SELECT coverage, coverage_reason, attempts FROM ' . Installer::table( 'run_urls' ) . ' WHERE run_id = %d', $id ), ARRAY_A );
		icheck( 'ok' === $url['coverage'], 'Read: ' . wp_json_encode( $url ) );
		icheck( 17 === Worker::slice_budget( 8, 15 ) && 20 === Worker::slice_budget( 20, 15 ), 'A slice fits one full request plus 2 seconds' );
		finish_active_runs();
	}
);

itest(
	'Branch review R1: a timeout after the full timeout is recorded at once; a deferral counts only when the URL had the whole slice',
	static function () use ( $admin ) {
		global $wpdb;
		finish_active_runs();
		reset_settings( array( 'timeout' => 15 ) );
		$repo   = new Repository();
		$id     = Scheduler::start_recheck( $admin, array( home_url( '/' ) ) );
		$client = timing_out_client();
		( new Worker( $client, static function () {} ) )->process( $id, 5 );
		$url = $wpdb->get_row( $wpdb->prepare( 'SELECT coverage, coverage_reason FROM ' . Installer::table( 'run_urls' ) . ' WHERE run_id = %d', $id ), ARRAY_A );
		icheck( 1 === $client->count && array( 15 ) === $client->timeouts, 'One request with the full timeout: ' . wp_json_encode( $client->timeouts ) );
		icheck( 'timeout' === $url['coverage'] && 'timeout' === $url['coverage_reason'], 'Recorded as the site\'s timeout: ' . wp_json_encode( $url ) );
		finish_active_runs();

		// Timeout 5, so a slice is 7 seconds: a 503 leaves no room for the
		// 2 second backoff and a full retry, so the page is deferred.
		reset_settings( array( 'timeout' => 5 ) );
		$busy   = home_url( '/r1-busy/' );
		$id     = Scheduler::start_recheck( $admin, array( home_url( '/' ), $busy ) );
		$client = new class() implements MLT\SchemaAudit\Engine\HttpClient {
			public $busy = 0;
			public function request( $url, $pinned_ip, array $args ) {
				if ( false !== strpos( $url, 'r1-busy' ) ) {
					++$this->busy;
					return array( 'status' => 503, 'error_code' => '', 'error' => '', 'headers' => array(), 'body' => '', 'truncated' => false, 'pinned' => true );
				}
				return array( 'status' => 200, 'error_code' => '', 'error' => '', 'headers' => array( 'content-type' => 'text/html' ), 'body' => '<html></html>', 'truncated' => false, 'pinned' => true );
			}
		};
		$row = static function () use ( $wpdb, $id ) {
			return $wpdb->get_row( $wpdb->prepare( "SELECT coverage, coverage_reason, attempts FROM {$wpdb->prefix}mltsa_run_urls WHERE run_id = %d AND url LIKE %s", $id, '%r1-busy%' ), ARRAY_A );
		};
		( new Worker( $client, static function () {} ) )->process( $id, 5 );
		$first = $row();
		$now   = $first;
		icheck( 1 === $client->busy && 'pending' === $first['coverage'] && 0 === (int) $first['attempts'], 'Deferred after another page in the slice: not counted ' . wp_json_encode( $first ) );
		// Branch review S1: each later slice continues the retries from where
		// the last stopped, so the page is recorded as the site refusing it,
		// not as the worker running out of time.
		for ( $i = 1; $i <= 20 && 'pending' === $now['coverage']; $i++ ) {
			usleep( 500000 );
			( new Worker( $client, static function () {} ) )->process( $id, 5 );
			$now = $row();
		}
		icheck( 3 === $client->busy, 'One request and two retries in all: ' . $client->busy );
		icheck( 'http_503' === $now['coverage_reason'], 'Recorded as refused with its status: ' . wp_json_encode( $now ) );
		finish_active_runs();
	}
);

itest(
	'Branch review R1: a file check is sent the full timeout and a timeout is recorded at once',
	static function () use ( $admin ) {
		finish_active_runs();
		reset_settings( array( 'timeout' => 15 ) );
		$repo  = new Repository();
		$id    = Scheduler::start_recheck( $admin, array( home_url( '/' ) ) );
		$image = home_url( '/wp-content/uploads/f4-logo.png' );
		$repo->update_run( $id, array( 'state' => 'running', 'phase' => 'resources', 'summary' => (string) wp_json_encode( array( 'resources' => array( $image => array() ) ) ) ) );
		$client = timing_out_client();
		( new Worker( $client, static function () {} ) )->process( $id, 5 );
		$run     = $repo->get_run( $id );
		$summary = Repository::decode( $run['summary'] );
		icheck( 1 === $client->count && array( 15 ) === $client->timeouts, 'One request with the full timeout: ' . wp_json_encode( $client->timeouts ) );
		icheck( 1 === (int) $summary['resource_index'] && 'resources' !== $run['phase'], 'Moved past the file' );
		icheck( ! isset( $summary['resource_attempts'] ), 'Attempt counter cleared' );
		finish_active_runs();
	}
);

itest(
	'Branch review S2: a slow HEAD refusal (405) followed by a GET that does not fit the slice never stalls the run',
	static function () use ( $admin ) {
		finish_active_runs();
		// Timeout 3, so a slice is 5 seconds: after a 2.5 second HEAD the GET
		// fallback has no full timeout left.
		reset_settings( array( 'timeout' => 3 ) );
		$repo = new Repository();
		$id   = Scheduler::start_recheck( $admin, array( home_url( '/' ) ) );
		$file = home_url( '/wp-content/uploads/s2-brochure.pdf' );
		$repo->update_run( $id, array( 'state' => 'running', 'phase' => 'resources', 'summary' => (string) wp_json_encode( array( 'resources' => array( $file => array() ) ) ) ) );
		$client = new class() implements MLT\SchemaAudit\Engine\HttpClient {
			public $log = array();
			public function request( $url, $pinned_ip, array $args ) {
				$this->log[] = $args['method'];
				if ( 'HEAD' === $args['method'] ) {
					usleep( 2500000 );
					return array( 'status' => 405, 'error_code' => '', 'error' => '', 'headers' => array(), 'body' => '', 'truncated' => false, 'pinned' => true );
				}
				return array( 'status' => 200, 'error_code' => '', 'error' => '', 'headers' => array( 'content-type' => 'application/pdf' ), 'body' => 'x', 'truncated' => false, 'pinned' => true );
			}
		};
		for ( $slice = 1; $slice <= 4; $slice++ ) {
			( new Worker( $client, static function () {} ) )->process( $id, 1 );
			$run = $repo->get_run( $id );
			if ( 'resources' !== $run['phase'] ) {
				break;
			}
		}
		$summary = Repository::decode( $run['summary'] );
		icheck( 'resources' !== $run['phase'] && 1 === (int) $summary['resource_index'], 'Moved past the file: ' . $run['phase'] . ' ' . wp_json_encode( $summary ) );
		icheck( $slice <= 3, 'Within three slices: ' . $slice . ' ' . implode( ',', $client->log ) );
		icheck( 0 === (int) $summary['resources_broken'] && 2 === count( $client->log ), 'The file is read by the GET in the next slice (branch review S1): ' . wp_json_encode( $summary ) );
		icheck( array( 'HEAD', 'GET' ) === $client->log, 'The HEAD is not sent again: ' . implode( ',', $client->log ) );
		finish_active_runs();
	}
);

itest(
	'Branch review S1 and S5: a page behind a slow redirect is read in the next slice, which WordPress cron queues at once',
	static function () use ( $admin ) {
		global $wpdb;
		finish_active_runs();
		// Timeout 3, so a slice is 5 seconds: after a 2.5 second first hop
		// the second has no full timeout left.
		reset_settings( array( 'timeout' => 3 ) );
		$old    = home_url( '/s1-old' );
		$id     = Scheduler::start_recheck( $admin, array( $old ) );
		$client = new class() implements MLT\SchemaAudit\Engine\HttpClient {
			public $log = array();
			public function request( $url, $pinned_ip, array $args ) {
				$this->log[] = $url;
				if ( false !== strpos( $url, 's1-old' ) ) {
					usleep( 2500000 );
					return array( 'status' => 301, 'error_code' => '', 'error' => '', 'headers' => array( 'location' => home_url( '/s1-new/' ) ), 'body' => '', 'truncated' => false, 'pinned' => true );
				}
				return array( 'status' => 200, 'error_code' => '', 'error' => '', 'headers' => array( 'content-type' => 'text/html' ), 'body' => '<html></html>', 'truncated' => false, 'pinned' => true );
			}
		};
		$row = static function () use ( $wpdb, $id ) {
			return $wpdb->get_row( $wpdb->prepare( "SELECT coverage, coverage_reason, final_url FROM {$wpdb->prefix}mltsa_run_urls WHERE run_id = %d AND url LIKE %s", $id, '%s1-old%' ), ARRAY_A );
		};
		for ( $slice = 1; $slice <= 4; $slice++ ) {
			Worker::tick( 1, new Worker( $client, static function () {} ) );
			$now = $row();
			if ( 1 === $slice ) {
				$next = wp_next_scheduled( Scheduler::WORKER_HOOK );
				icheck( $next && $next <= time(), 'A slice cut short queues the next worker event at once: ' . ( $next ? $next - time() : 'none' ) );
			}
			if ( $now && 'pending' !== $now['coverage'] ) {
				break;
			}
		}
		$hops = count( array_filter( $client->log, static function ( $url ) { return false !== strpos( $url, 's1-old' ); } ) );
		icheck( $now && 'pending' !== $now['coverage'] && false !== strpos( (string) $now['final_url'], 's1-new' ), 'Read through the redirect: ' . wp_json_encode( $now ) );
		icheck( 1 === $hops, 'The first hop is requested once: ' . implode( ',', $client->log ) );
		finish_active_runs();
		Scheduler::clear_worker();
	}
);

itest(
	'Branch review S3: a monthly audit refused while the upgrade was pending starts from the hourly watchdog once it completes',
	static function () {
		$repo = new Repository();
		finish_active_runs();
		reset_settings( array( 'monitoring' => true ) );
		$s        = Settings::all();
		$previous = Calendar::previous( $s, time() );
		update_option( 'mltsa_monitoring_since', $previous - 86400, false );
		$key      = Calendar::schedule_key( $previous, $s['schedule_timezone'] );
		$existing = $repo->run_by_schedule_key( $key );
		if ( $existing ) {
			global $wpdb;
			$wpdb->update( $wpdb->prefix . 'mltsa_runs', array( 'schedule_key' => null ), array( 'id' => (int) $existing['id'] ) );
		}
		$saved = get_option( 'mltsa_db_version' );
		update_option( 'mltsa_db_version', '1', false );
		try {
			icheck( 0 === Scheduler::start_monthly( $previous, false ), 'Refused while the upgrade is pending' );
		} finally {
			update_option( 'mltsa_db_version', $saved, false );
		}
		icheck( ! $repo->run_by_schedule_key( $key ), 'No run yet' );
		Scheduler::on_watchdog();
		$run = $repo->run_by_schedule_key( $key );
		icheck( $run && 'monthly' === $run['run_type'], 'The watchdog started the missed month as a catch-up' );
		finish_active_runs();
		Scheduler::clear_worker();
	}
);

itest(
	'Owner decision 2026-11-02: an own-host sameAs link is checked as a page (URL-008), an image as a file (URL-004)',
	static function () use ( $admin ) {
		finish_active_runs();
		reset_settings( array( 'timeout' => 15 ) );
		global $wpdb;
		$repo    = new Repository();
		$id      = Scheduler::start_recheck( $admin, array( home_url( '/' ) ) );
		$link    = home_url( '/team/gone-person/' );
		$pdf     = home_url( '/wp-content/uploads/profile.pdf' );
		$image   = home_url( '/wp-content/uploads/gone-logo.png' );
		$where   = static function ( $prop ) {
			return array(
				array(
					'url_id' => 0,
					'prop'   => $prop,
					'path'   => "$['" . $prop . "']",
					'block'  => 0,
				),
			);
		};
		$summary = array(
			'resources' => array(
				$link  => $where( 'sameAs' ),
				$pdf   => $where( 'sameAs' ),
				$image => $where( 'logo' ),
			),
		);
		$repo->update_run( $id, array( 'state' => 'running', 'phase' => 'resources', 'summary' => (string) wp_json_encode( $summary ) ) );
		$client = new class() implements MLT\SchemaAudit\Engine\HttpClient {
			public $seen = array();
			public function request( $url, $pinned_ip, array $args ) {
				$this->seen[] = $args['method'] . ' ' . $url;
				return array( 'status' => 404, 'error_code' => '', 'error' => '', 'headers' => array(), 'body' => '', 'truncated' => false, 'pinned' => true );
			}
		};
		// The outcomes are dropped from the summary after reconcile, so keep
		// the last summary the resource step wrote.
		$written = '';
		$capture = static function ( $query ) use ( &$written ) {
			if ( false !== strpos( $query, 'resource_outcomes' ) && false === strpos( $query, 'resource_attempts' ) ) {
				$written = $query;
			}
			return $query;
		};
		add_filter( 'query', $capture );
		( new Worker( $client, static function () {} ) )->process( $id, 5 );
		remove_filter( 'query', $capture );
		icheck( array( 'HEAD ' . $link, 'HEAD ' . $image ) === $client->seen, 'Requests: ' . wp_json_encode( $client->seen ) );
		icheck( 2 === substr_count( $written, 'not_found' ), 'The link and the image answered 404: ' . $written );
		icheck( 1 === substr_count( $written, 'blocked' ), 'A sameAs link into /wp-content/ is refused by the page policy, not fetched as a file' );
		$rules = $wpdb->get_col( $wpdb->prepare( 'SELECT CONCAT(rule_id, \' \', observed) FROM ' . Installer::table( 'occurrences' ) . ' WHERE run_id = %d ORDER BY rule_id', $id ) );
		icheck( array( 'URL-004 ' . $image, 'URL-008 ' . $link ) === $rules, 'Findings: ' . wp_json_encode( $rules ) );
		finish_active_runs();
	}
);

itest(
	'F4 review 2026-10-30: a tick that dies part way still leaves a worker event queued, after the lock expires',
	static function () use ( $admin ) {
		finish_active_runs();
		reset_settings( array( 'timeout' => 15 ) );
		$id = Scheduler::start_recheck( $admin, array( home_url( '/' ) ) );
		Scheduler::clear_worker();
		$die = static function () {
			throw new RuntimeException( 'process killed' );
		};
		add_filter( 'pre_http_request', $die );
		$before = time();
		try {
			Worker::tick( 5 );
			icheck( false, 'The tick should have died' );
		} catch ( RuntimeException $e ) {
			icheck( 'process killed' === $e->getMessage(), 'Died in the request: ' . $e->getMessage() );
		} finally {
			remove_filter( 'pre_http_request', $die );
		}
		$next = wp_next_scheduled( 'mltsa_worker' );
		// The slice is raised to fit one full request (branch review R1): 17 s.
		$slice = Worker::slice_budget( 5, 15 );
		icheck( $next && $next >= $before + $slice + Worker::CONTINUATION_GRACE && $next <= time() + $slice + Worker::CONTINUATION_GRACE, 'Continuation queued after the budget and lock: ' . ( $next - $before ) );
		icheck( $slice + 120 < Worker::CONTINUATION_GRACE + $slice, 'Fires after the run lock (budget + 120 s) has expired' );
		icheck( wp_next_scheduled( 'mltsa_watchdog' ), 'Watchdog queued' );
		finish_active_runs();
		Scheduler::clear_worker();
		Worker::tick( 5 );
		icheck( ! wp_next_scheduled( 'mltsa_worker' ), 'An idle tick queues no worker event' );
	}
);

itest(
	'F4 review 2026-10-30: the hourly watchdog requeues a worker for an active run that has none',
	static function () use ( $admin ) {
		finish_active_runs();
		reset_settings();
		$id = Scheduler::start_recheck( $admin, array( home_url( '/' ) ) );
		Scheduler::clear_worker();
		Scheduler::on_watchdog();
		icheck( wp_next_scheduled( 'mltsa_worker' ), 'Worker requeued' );
		global $wpdb;
		$events = (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM ' . Installer::table( 'events' ) . " WHERE event_type = 'worker_restarted' AND run_id = %d", $id ) );
		icheck( 1 === $events, 'Restart logged against the run' );
		Scheduler::on_watchdog();
		icheck( 1 === (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM ' . Installer::table( 'events' ) . " WHERE event_type = 'worker_restarted' AND run_id = %d", $id ) ), 'Nothing done while a worker is queued' );
		finish_active_runs();
		Scheduler::clear_worker();
	}
);

itest(
	'Review ENG-4: latest notes for a findings export come from one query per 500 issues, same answer as one query each',
	static function () {
		global $wpdb;
		$repo  = new Repository();
		$table = Installer::table( 'events' );
		$base  = 9100000;
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$table} WHERE object_type = 'issue' AND object_id BETWEEN %d AND %d", $base, $base + 2000 ) );
		$repo->log_event( 'note', array( 'text' => 'first' ), 1, 'issue', $base + 1 );
		$repo->log_event( 'status', array( 'to' => 'open' ), 1, 'issue', $base + 1 );
		$repo->log_event( 'note', array( 'text' => 'second' ), 1, 'issue', $base + 1 );
		$repo->log_event( 'status', array( 'to' => 'open' ), 1, 'issue', $base + 2 );
		$repo->log_event( 'note', array( 'other' => 'no text' ), 1, 'issue', $base + 3 );
		$repo->log_event( 'note', array( 'text' => 'not an issue' ), 1, 'run', $base + 4 );
		$repo->log_event( 'note', array( 'text' => 'other issue' ), 1, 'issue', $base + 5 );
		$ids = array( $base + 1, $base + 2, $base + 3, $base + 4, $base + 5, $base + 6, $base + 1 );

		// The old behaviour: one query per issue, the last note event wins.
		$expected = array();
		foreach ( array_unique( $ids ) as $id ) {
			foreach ( $repo->events_for( 'issue', $id ) as $event ) {
				if ( 'note' === $event['event_type'] ) {
					$data            = Repository::decode( $event['data'] );
					$expected[ $id ] = isset( $data['text'] ) ? (string) $data['text'] : '';
				}
			}
		}
		$before = $wpdb->num_queries;
		$got    = \MLT\SchemaAudit\Issues::latest_notes( $ids );
		$used   = $wpdb->num_queries - $before;
		ksort( $got );
		ksort( $expected );
		icheck( $expected === $got, 'Same output as the per-issue loop: ' . wp_json_encode( $got ) . ' vs ' . wp_json_encode( $expected ) );
		icheck( array( $base + 1 => 'second', $base + 3 => '', $base + 5 => 'other issue' ) === $got, 'Latest note wins; no text gives an empty string; other object types and non-note events ignored' );
		icheck( 1 === $used, 'One query for a small set, used ' . $used );

		$many = range( $base + 1, $base + 1200 );
		$before = $wpdb->num_queries;
		$got    = \MLT\SchemaAudit\Issues::latest_notes( $many );
		icheck( 3 === $wpdb->num_queries - $before, 'Three queries for 1200 issues, used ' . ( $wpdb->num_queries - $before ) );
		icheck( 'second' === $got[ $base + 1 ], 'Chunked read gives the same answer' );
		icheck( array() === \MLT\SchemaAudit\Issues::latest_notes( array() ), 'Empty list, no result' );
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$table} WHERE object_id BETWEEN %d AND %d AND object_type IN ('issue','run')", $base, $base + 2000 ) );
	}
);

itest(
	'Review finding 9: the issue register lists every issue across runs with owner, status and verification filters, for capability holders only',
	static function () use ( $admin ) {
		global $wpdb;
		$repo   = new Repository();
		$table  = Installer::table( 'issues' );
		$prefix = 'mltsa-register-test-';
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$table} WHERE page_url LIKE %s", 'https://register-test.example.invalid/%' ) );
		$make = static function ( $tag, array $over ) use ( $repo, $prefix ) {
			return $repo->insert_issue(
				array_merge(
					array(
						'issue_key'          => sha1( $prefix . $tag ),
						'page_url'           => 'https://register-test.example.invalid/' . $tag . '/',
						'rule_id'            => 'FACT-006',
						'severity'           => 'medium',
						'first_observed_utc' => '2026-09-01 10:00:00',
						'last_observed_utc'  => '2026-09-01 10:00:00',
						'verification_state' => 'present',
						'work_status'        => 'open',
					),
					$over
				)
			);
		};
		$a = $make( 'a', array( 'owner_user_id' => $admin, 'last_observed_utc' => '2026-09-03 10:00:00' ) );
		$b = $make( 'b', array( 'rule_id' => 'ID-003', 'site_wide' => 1, 'work_status' => 'resolved', 'verification_state' => 'unavailable', 'last_observed_utc' => '2026-09-02 10:00:00' ) );
		$c = $make( 'c', array( 'rule_id' => 'SYN-001', 'work_status' => 'in_progress', 'verification_state' => 'no_longer_detected', 'owner_user_id' => $admin, 'page_url' => 'https://register-test.example.invalid/c/"><script>alert(9)</script>' ) );
		list( $cookie ) = session_for( $admin );
		$get = static function ( $query ) use ( $cookie ) {
			return http( 'GET', '/wp-admin/admin.php?page=mltsa-register' . $query, $cookie );
		};
		$has = static function ( $body, $id ) {
			return false !== strpos( $body, 'issue=' . $id . '"' ) || false !== strpos( $body, 'issue=' . $id . '&' );
		};

		// Not tied to one run: these issues have no occurrence in any run, and still list.
		$r = $get( '&s=register-test.example.invalid' );
		icheck( 200 === $r['status'], 'Register renders: ' . $r['status'] );
		icheck( $has( $r['body'], $a ) && $has( $r['body'], $b ) && $has( $r['body'], $c ), 'All three issues listed with no run selected' );
		icheck( false !== strpos( $r['body'], '3 issues in the register' ), 'Count shown' );
		icheck( false === strpos( $r['body'], '<script>alert(9)' ) && false !== strpos( $r['body'], '&lt;script&gt;alert(9)' ), 'Page URL escaped' );
		icheck( false !== strpos( $r['body'], '(site-wide)' ), 'Site-wide issue labelled' );
		$pos = static function ( $body, $id ) {
			return strpos( $body, 'issue=' . $id . '"' );
		};
		icheck( $pos( $r['body'], $a ) < $pos( $r['body'], $b ) && $pos( $r['body'], $b ) < $pos( $r['body'], $c ), 'Newest last observation first' );

		$only = static function ( $body, array $ids ) use ( $has, $a, $b, $c ) {
			foreach ( array( $a, $b, $c ) as $id ) {
				if ( $has( $body, $id ) !== in_array( $id, $ids, true ) ) {
					return false;
				}
			}
			return true;
		};
		$r = $get( '&s=register-test.example.invalid&owner=' . $admin );
		icheck( $only( $r['body'], array( $a, $c ) ), 'Owner filter' );
		$r = $get( '&s=register-test.example.invalid&owner=none' );
		icheck( $only( $r['body'], array( $b ) ), 'Owner filter: nobody' );
		$r = $get( '&s=register-test.example.invalid&work_status=in_progress' );
		icheck( $only( $r['body'], array( $c ) ), 'Status filter' );
		$r = $get( '&s=register-test.example.invalid&verification_state=unavailable' );
		icheck( $only( $r['body'], array( $b ) ), 'Verification filter' );
		$r = $get( '&s=register-test.example.invalid&work_status=open&owner=' . $admin . '&verification_state=present' );
		icheck( $only( $r['body'], array( $a ) ), 'Filters combine' );
		$r = $get( '&s=register-test.example.invalid&work_status=%27%20OR%201%3D1' );
		icheck( 200 === $r['status'] && $only( $r['body'], array( $a, $b, $c ) ), 'An unknown status value is ignored, not run as SQL' );
		$r = $get( '&s=' . rawurlencode( "%' OR 1=1 --" ) );
		icheck( 200 === $r['status'] && false !== strpos( $r['body'], '0 issues in the register' ), 'SQL metacharacters in search match nothing' );

		// Paging.
		for ( $n = 0; $n < 52; $n++ ) {
			$make( 'fill' . $n, array( 'page_url' => 'https://register-test.example.invalid/fill/' . $n ) );
		}
		$r1 = $get( '&s=register-test.example.invalid%2Ffill' );
		$r2 = $get( '&s=register-test.example.invalid%2Ffill&paged=2' );
		icheck( false !== strpos( $r1['body'], '52 issues in the register' ) && false !== strpos( $r1['body'], 'Page 1 of 2' ), 'First page of two' );
		icheck( false !== strpos( $r2['body'], 'Page 2 of 2' ) && 2 === substr_count( $r2['body'], 'register-test.example.invalid/fill/' ), 'Second page holds the remaining two' );

		// The findings screen points to it, and the issue link works.
		$f = http( 'GET', '/wp-admin/admin.php?page=mltsa-findings', $cookie );
		icheck( false !== strpos( $f['body'], 'page=mltsa-register' ), 'Findings screen links to the register' );
		$d = http( 'GET', '/wp-admin/admin.php?page=mltsa-findings&issue=' . $a, $cookie );
		icheck( 200 === $d['status'] && false !== strpos( $d['body'], 'FACT-006' ), 'Issue link opens the issue' );

		// Access control.
		foreach ( array( 'anonymous' => 0, 'subscriber' => test_user( 'mltsa_test_subscriber', 'subscriber' ), 'editor' => test_user( 'mltsa_test_editor', 'editor' ), 'admin_no_caps' => test_user( 'mltsa_test_admin_nocap', 'administrator', true ) ) as $label => $uid ) {
			list( $other ) = session_for( $uid );
			$r             = http( 'GET', '/wp-admin/admin.php?page=mltsa-register', $other );
			icheck( in_array( $r['status'], array( 302, 403 ), true ) && false === strpos( $r['body'], 'register-test.example.invalid' ) && false === strpos( $r['body'], 'mltsa-coverage' ), "{$label} sees the register: {$r['status']}" );
		}
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$table} WHERE page_url LIKE %s", 'https://register-test.example.invalid/%' ) );
	}
);

itest(
	'Argon BUG-3 check: the size cap counts decompressed bytes, so a small gzip body of a page under the cap is not truncated',
	static function () {
		// cURL decodes the body before the HTTP API's write callback counts
		// it (CURLOPT_ENCODING ''), so limit_response_size and strlen() both
		// measure the decompressed page.
		$probe = ABSPATH . 'mltsa-gzip-probe.php';
		file_put_contents( $probe, "<?php\n\$n = (int) \$_GET['n'];\n\$gz = gzencode( '<html><body>' . str_repeat( 'a', \$n - 26 ) . '</body></html>', 9 );\nheader( 'Content-Type: text/html' );\nheader( 'Content-Encoding: gzip' );\nheader( 'Content-Length: ' . strlen( \$gz ) );\necho \$gz;\n" );
		try {
			$client = new MLT\SchemaAudit\Engine\WpHttpClient();
			$cap    = 5242880;
			$args   = array( 'timeout' => 20, 'max_bytes' => $cap, 'user_agent' => 'mltsa-test' );
			$small  = $client->request( home_url( '/mltsa-gzip-probe.php?n=4000000' ), '127.0.0.1', $args );
			icheck( 200 === $small['status'] && $small['pinned'], 'Probe answered through the pinned connection: ' . $small['error'] );
			icheck( 'gzip' === $small['headers']['content-encoding'] && (int) $small['headers']['content-length'] < 100000, 'Sent compressed: ' . $small['headers']['content-length'] );
			icheck( 4000000 === strlen( $small['body'] ) && false === $small['truncated'], 'A 4,000,000 byte page arrives whole: ' . strlen( $small['body'] ) );
			$big = $client->request( home_url( '/mltsa-gzip-probe.php?n=6000000' ), '127.0.0.1', $args );
			icheck( $cap === strlen( $big['body'] ) && true === $big['truncated'], 'A 6,000,000 byte page is cut at the cap: ' . strlen( $big['body'] ) );
			icheck( (int) $big['headers']['content-length'] < $cap, 'Even though its compressed size is far under the cap' );
		} finally {
			unlink( $probe );
		}
	}
);

itest(
	'Review reply: a page of exactly the size cap is whole; one byte more is cut to the cap and flagged',
	static function () {
		$probe = ABSPATH . 'mltsa-size-probe.php';
		file_put_contents( $probe, "<?php\n\$n = (int) \$_GET['n'];\n\$page = '<html><body>' . str_repeat( 'a', \$n - 26 ) . '</body></html>';\nheader( 'Content-Type: text/html' );\nif ( ! empty( \$_GET['gz'] ) ) {\n\t\$page = gzencode( \$page, 9 );\n\theader( 'Content-Encoding: gzip' );\n}\nheader( 'Content-Length: ' . strlen( \$page ) );\necho \$page;\n" );
		try {
			$client = new MLT\SchemaAudit\Engine\WpHttpClient();
			$cap    = 5242880;
			$args   = array( 'timeout' => 20, 'max_bytes' => $cap, 'user_agent' => 'mltsa-test' );
			foreach ( array( 0, 1 ) as $gz ) {
				$label = $gz ? 'gzip' : 'plain';
				$exact = $client->request( home_url( '/mltsa-size-probe.php?gz=' . $gz . '&n=' . $cap ), '127.0.0.1', $args );
				icheck( 200 === $exact['status'] && $exact['pinned'], $label . ': probe answered through the pinned connection: ' . $exact['error'] );
				icheck( $cap === strlen( $exact['body'] ) && false === $exact['truncated'], $label . ': a page of exactly ' . $cap . ' bytes is whole, not truncated: ' . strlen( $exact['body'] ) );
				icheck( '</body></html>' === substr( $exact['body'], -14 ), $label . ': its closing tags arrived' );
				$over = $client->request( home_url( '/mltsa-size-probe.php?gz=' . $gz . '&n=' . ( $cap + 1 ) ), '127.0.0.1', $args );
				icheck( $cap === strlen( $over['body'] ) && true === $over['truncated'], $label . ': a page of cap + 1 bytes is cut to the cap and flagged: ' . strlen( $over['body'] ) );
			}
		} finally {
			unlink( $probe );
		}
	}
);

itest(
	'MySQL: a recipient longer than the 254-character outbox column is refused, not cut; one row per recipient still holds',
	static function () {
		$domain = '@' . str_repeat( 'b', 60 ) . '.' . str_repeat( 'c', 60 ) . '.' . str_repeat( 'd', 60 ) . '.example';
		$ok     = str_repeat( 'a', 254 - strlen( $domain ) ) . $domain;
		$long   = 'a' . $ok;
		$errors = array();
		icheck( array( $ok ) === Settings::sanitise( 'recipients', $ok, $errors ) && array() === $errors, 'A 254-character address is accepted' );
		$errors = array();
		icheck( null === Settings::sanitise( 'recipients', $long, $errors ) && 1 === count( $errors ), 'A 255-character address is refused: ' . wp_json_encode( $errors ) );
		$repo  = new Repository();
		$row   = array(
			'run_id'            => 999999,
			'notification_type' => 'digest',
			'recipient'         => $ok,
		);
		$first = $repo->insert_outbox( $row );
		icheck( $first > 0 && 0 === $repo->insert_outbox( $row ), 'Second row for the same recipient refused' );
		global $wpdb;
		$stored = $wpdb->get_var( $wpdb->prepare( 'SELECT recipient FROM ' . Installer::table( 'outbox' ) . ' WHERE id = %d', $first ) );
		icheck( $ok === $stored, 'Stored whole' );
		$suppress = $wpdb->suppress_errors( true );
		$dup      = $wpdb->insert( Installer::table( 'outbox' ), $row + array( 'created_utc' => Repository::now() ) );
		$wpdb->suppress_errors( $suppress );
		icheck( false === $dup, 'The unique key (recipient indexed to 191 characters on MySQL) refuses a direct duplicate' );
		$wpdb->query( $wpdb->prepare( 'DELETE FROM ' . Installer::table( 'outbox' ) . ' WHERE run_id = %d', 999999 ) );
	}
);

/**
 * What Admin::handle_cancel() does, without its redirect.
 *
 * @param int $id Run ID.
 */
function cancel_like_admin( $id ) {
	icheck( ( new Repository() )->cancel_run( $id ), 'Cancel applied to the active run' );
}

itest(
	'Argon BUG-5: a cancel issued while the worker is part way through a step wins in the fetch phase; in the final step it is refused (R4)',
	static function () use ( $admin, $hostile_url ) {
		global $wpdb;
		$repo = new Repository();

		// 1. Cancel during a page request: the worker makes no further
		// request, and the run stays cancelled with phase done.
		finish_active_runs();
		reset_settings();
		$id     = Scheduler::start_recheck( $admin, array( home_url( '/' ), $hostile_url ) );
		$client = new class( $id ) implements MLT\SchemaAudit\Engine\HttpClient {
			public $count = 0;
			private $run;
			public function __construct( $run ) {
				$this->run = $run;
			}
			public function request( $url, $pinned_ip, array $args ) {
				++$this->count;
				if ( 1 === $this->count ) {
					cancel_like_admin( $this->run );
				}
				return array( 'status' => 200, 'headers' => array( 'content-type' => 'text/html' ), 'body' => '<html><head><title>t</title></head><body>x</body></html>', 'error' => '', 'error_code' => '', 'pinned' => true, 'truncated' => false );
			}
		};
		( new Worker( $client, static function () {} ) )->process( $id, 30 );
		$run = $repo->get_run( $id );
		icheck( 'cancelled' === $run['state'] && 'done' === $run['phase'], 'Fetch phase: ' . $run['state'] . '/' . $run['phase'] );
		$requests = $client->count;

		// 2. Cancel while the final step is running: the register has been
		// written, so the cancel is refused and the run completes as one
		// (branch review R4; before, the cancel won and the register kept a
		// cancelled run's changes).
		finish_active_runs();
		$id    = Scheduler::start_recheck( $admin, array( home_url( '/' ) ) );
		$fired = false;
		$hook  = static function ( $query ) use ( $id, &$fired ) {
			global $wpdb;
			if ( ! $fired && false !== strpos( $query, 'SELECT coverage, COUNT(*)' ) && false !== strpos( $query, 'run_id = ' . $id ) ) {
				$fired = true;
				$phase = $wpdb->get_var( $wpdb->prepare( "SELECT phase FROM {$wpdb->prefix}mltsa_runs WHERE id = %d", $id ) );
				if ( 'notify' === $phase ) {
					icheck( false === ( new Repository() )->cancel_run( $id ), 'Cancel refused once the register is written' );
				} else {
					$fired = false;
				}
			}
			return $query;
		};
		add_filter( 'query', $hook );
		try {
			( new Worker() )->process( $id, 60 );
		} finally {
			remove_filter( 'query', $hook );
		}
		$run = $repo->get_run( $id );
		icheck( $fired, 'The cancel was issued during the final step' );
		icheck( 'complete' === $run['state'] && 'done' === $run['phase'], 'Final step: ' . $run['state'] . '/' . $run['phase'] );
		$finished = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$wpdb->prefix}mltsa_events WHERE event_type = 'run_finished' AND run_id = %d", $id ) );
		icheck( 1 === $finished, 'Logged as finished once: ' . $finished );
		icheck( 1 === $requests, 'No request after the cancel in the fetch phase: ' . $requests );

		// 3. The other way round: a cancel that arrives after the run
		// finished leaves its outcome alone.
		finish_active_runs();
		$id = Scheduler::start_recheck( $admin, array( home_url( '/' ) ) );
		( new Worker() )->process( $id, 60 );
		icheck( 'complete' === $repo->get_run( $id )['state'], 'Recheck finished' );
		icheck( false === $repo->cancel_run( $id ), 'A late cancel reports nothing cancelled' );
		icheck( 'complete' === $repo->get_run( $id )['state'], 'And the run stays complete' );
		finish_active_runs();
	}
);

itest(
	'Argon BUG-4: with MLTSA_ALLOW_PRIVATE_SELF, the www or bare variant of a private home host is not refused a second time by WordPress',
	static function () {
		// example.test does not resolve here, and WordPress looks the host
		// up itself, so the *.localhost names (which resolve to 127.0.0.1)
		// stand in for a local development site and its www variant.
		$probe = ABSPATH . 'mltsa-host-probe.php';
		file_put_contents( $probe, "<?php\necho 'probe-ok';\n" );
		$args  = array( 'timeout' => 10, 'max_bytes' => 100000, 'user_agent' => 'mltsa-test' );
		$home  = '';
		$force = static function () use ( &$home ) {
			return $home;
		};
		add_filter( 'pre_option_home', $force );
		try {
			foreach ( array( 'example.localhost', 'www.example.localhost' ) as $home_host ) {
				$home = 'http://' . $home_host . ':8899';
				foreach ( array( 'example.localhost', 'www.example.localhost' ) as $host ) {
					$url = 'http://' . $host . ':8899/mltsa-host-probe.php';
					$on  = ( new MLT\SchemaAudit\Engine\WpHttpClient( true ) )->request( $url, '127.0.0.1', $args );
					icheck( 200 === $on['status'] && 'probe-ok' === $on['body'], "Allowed with the constant, home {$home_host}, URL {$host}: {$on['status']} {$on['error']}" );
					if ( $host !== $home_host ) {
						$off = ( new MLT\SchemaAudit\Engine\WpHttpClient( false ) )->request( $url, '127.0.0.1', $args );
						icheck( 0 === $off['status'] && '' !== $off['error'], "Still refused without the constant, home {$home_host}, URL {$host}" );
						// The pinned address decides: link-local and metadata never pass.
						foreach ( array( '169.254.169.254', '169.254.10.10' ) as $bad ) {
							$t0  = microtime( true );
							$res = ( new MLT\SchemaAudit\Engine\WpHttpClient( true ) )->request( $url, $bad, $args );
							icheck( 0 === $res['status'] && microtime( true ) - $t0 < 2, "Refused before connecting when pinned to {$bad}: {$res['error']}" );
						}
					}
				}
				// Any other host stays refused.
				$other = ( new MLT\SchemaAudit\Engine\WpHttpClient( true ) )->request( 'http://other.localhost:8899/mltsa-host-probe.php', '127.0.0.1', $args );
				icheck( 0 === $other['status'], "Another host is refused, home {$home_host}" );
			}
		} finally {
			remove_filter( 'pre_option_home', $force );
			unlink( $probe );
		}
	}
);

itest(
	'Review reply: the database upgrade from version 1 adds the issues evidence column, keeps the data, records the version and can run twice',
	static function () {
		global $wpdb;
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		// Build the version 1 tables under a separate prefix, so the site's
		// own tables are not touched (this SQLite layer has no RENAME).
		$real_prefix    = $wpdb->prefix;
		$saved_version  = get_option( 'mltsa_db_version' );
		$wpdb->prefix   = $real_prefix . 'mltsaupg_';
		$issues         = Installer::table( 'issues' );
		try {
			// The issues table as database version 1 created it (before review fix 2).
			dbDelta(
				"CREATE TABLE {$issues} (
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
) " . $wpdb->get_charset_collate() . ';'
			);
			$columns = $wpdb->get_col( "SHOW COLUMNS FROM {$issues}" );
			icheck( in_array( 'work_status', $columns, true ) && ! in_array( 'evidence', $columns, true ), 'Version 1 table built: ' . implode( ',', $columns ) );
			$row = array(
				'issue_key'          => sha1( 'upgrade-test' ),
				'page_url'           => 'https://upgrade-test.example.invalid/a/',
				'rule_id'            => 'FACT-001',
				'severity'           => 'high',
				'work_status'        => 'in_progress',
				'owner_user_id'      => 7,
				'external_link'      => 'https://tracker.example.invalid/1',
				'exception_reason'   => 'Kept through the upgrade',
				'verification_state' => 'unavailable',
			);
			icheck( false !== $wpdb->insert( $issues, $row ), 'Version 1 row stored: ' . $wpdb->last_error );
			update_option( 'mltsa_db_version', '1', false );
			icheck( get_option( 'mltsa_db_version' ) !== MLTSA_DB_VERSION, 'Plugin::boot() sees an old schema and upgrades' );

			// A database that refuses the new column: the version is not
			// recorded, so the upgrade is tried again later.
			$refuse = static function ( $query ) {
				return preg_match( '/^ALTER TABLE \S+ ADD COLUMN `?evidence/i', $query ) ? 'ALTER TABLE no_such_mltsa_table ADD COLUMN evidence longtext' : $query;
			};
			add_filter( 'query', $refuse );
			try {
				Installer::create_tables();
			} finally {
				remove_filter( 'query', $refuse );
			}
			icheck( ! in_array( 'evidence', $wpdb->get_col( "SHOW COLUMNS FROM {$issues}" ), true ), 'Column refused in this step' );
			icheck( '1' === get_option( 'mltsa_db_version' ) && ! Installer::schema_ready(), 'Version not recorded after a refused upgrade: ' . get_option( 'mltsa_db_version' ) );

			Installer::create_tables();
			icheck( '' === $wpdb->last_error, 'Upgrade ran without a database error: ' . $wpdb->last_error );
			$after = $wpdb->get_col( "SHOW COLUMNS FROM {$issues}" );
			icheck( in_array( 'evidence', $after, true ), 'evidence column added: ' . implode( ',', $after ) );
			icheck( MLTSA_DB_VERSION === get_option( 'mltsa_db_version' ), 'Version recorded: ' . get_option( 'mltsa_db_version' ) );
			$kept = $wpdb->get_row( "SELECT * FROM {$issues}", ARRAY_A );
			foreach ( $row as $key => $value ) {
				icheck( (string) $value === (string) $kept[ $key ], "{$key} kept: " . $kept[ $key ] );
			}
			icheck( '' === (string) $kept['evidence'], 'Existing issue has empty evidence, which reconciliation treats as "stored before evidence"' );
			icheck( 1 === (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$issues}" ), 'One row' );
			$wpdb->update( $issues, array( 'evidence' => '["upgrade-test"]' ), array( 'id' => (int) $kept['id'] ) );

			// Twice is harmless: no error, same columns, same row.
			Installer::create_tables();
			icheck( '' === $wpdb->last_error, 'Second run without error: ' . $wpdb->last_error );
			icheck( $after === $wpdb->get_col( "SHOW COLUMNS FROM {$issues}" ), 'Same columns after a second run' );
			$again = $wpdb->get_row( "SELECT * FROM {$issues}", ARRAY_A );
			icheck( '["upgrade-test"]' === $again['evidence'] && 'in_progress' === $again['work_status'] && 1 === (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$issues}" ), 'Data unchanged by a second run' );
			$dup = $wpdb->insert( $issues, array( 'issue_key' => sha1( 'upgrade-test' ), 'rule_id' => 'FACT-001', 'evidence' => '', 'exception_reason' => '' ) );
			icheck( false === $dup, 'The unique issue_key index survived the upgrade' );
		} finally {
			foreach ( Installer::TABLES as $suffix ) {
				$wpdb->query( 'DROP TABLE IF EXISTS ' . Installer::table( $suffix ) );
			}
			$wpdb->prefix = $real_prefix;
			update_option( 'mltsa_db_version', $saved_version, false );
		}
	}
);

itest(
	'Review reply: findings held as unavailable in audits in a row show as a coverage figure on the audit screen and in the export, and keep their state',
	static function () use ( $admin, $hostile_url ) {
		global $wpdb;
		$repo = new Repository();
		finish_active_runs();
		reset_settings( array( 'timeout' => 15 ) );
		$id = Scheduler::start_recheck( $admin, array( $hostile_url ) );
		( new Worker() )->process( $id, 60 );
		$key   = MLT\SchemaAudit\Engine\Evaluator::url_key( $hostile_url );
		$ids   = array_map( 'intval', $wpdb->get_col( $wpdb->prepare( "SELECT DISTINCT issue_id FROM {$wpdb->prefix}mltsa_occurrences WHERE run_id = %d AND issue_id > 0", $id ) ) );
		icheck( count( $ids ) > 0, 'The page has issues' );
		$wpdb->query( $wpdb->prepare( "UPDATE {$wpdb->prefix}mltsa_issues SET work_status = 'in_progress' WHERE id = %d", $ids[0] ) );

		$runs = array();
		for ( $i = 1; $i <= 2; $i++ ) {
			$rid = Scheduler::start_recheck( $admin, array( $hostile_url ) );
			( new Worker( timing_out_client(), static function () {} ) )->process( $rid, 60 );
			$runs[ $i ] = $repo->get_run( $rid );
			icheck( in_array( $runs[ $i ]['state'], array( 'failed', 'partial' ), true ), "Audit {$i} could not read the page: " . $runs[ $i ]['state'] );
		}
		$one = Repository::decode( $runs[1]['summary'] );
		$two = Repository::decode( $runs[2]['summary'] );
		icheck( count( $ids ) === (int) $one['register']['unavailable'] && 0 === (int) $one['repeat_unavailable']['issues'], 'First audit: unavailable once, not yet repeated: ' . wp_json_encode( $one['repeat_unavailable'] ) );
		icheck( count( $ids ) === (int) $two['repeat_unavailable']['issues'] && 2 === (int) $two['repeat_unavailable']['longest'], 'Second audit: every issue unavailable twice in a row: ' . wp_json_encode( $two['repeat_unavailable'] ) );
		$listed = $two['repeat_unavailable']['ids'];
		sort( $listed );
		$expect = $ids;
		sort( $expect );
		icheck( $expect === $listed, 'Which issues: ' . wp_json_encode( $listed ) );

		// Read-only: states as reconciliation set them, work status untouched.
		$states = $wpdb->get_results( 'SELECT id, verification_state, work_status FROM ' . $wpdb->prefix . 'mltsa_issues WHERE id IN (' . implode( ',', $ids ) . ')', ARRAY_A );
		foreach ( $states as $row ) {
			icheck( 'unavailable' === $row['verification_state'], 'Still unavailable: ' . $row['id'] );
			icheck( ( (int) $row['id'] === $ids[0] ? 'in_progress' : 'open' ) === $row['work_status'], 'Work status untouched: ' . $row['id'] . ' ' . $row['work_status'] );
		}

		list( $cookie ) = session_for( $admin );
		$screen = http( 'GET', '/wp-admin/admin.php?page=mltsa&run=' . (int) $runs[2]['id'], $cookie );
		icheck( false !== strpos( $screen['body'], 'Unavailable in 2 or more audits in a row: ' . count( $ids ) ), 'Audit screen shows the figure' );
		icheck( false !== strpos( $screen['body'], 'issue=' . $ids[0] ) && false !== strpos( $screen['body'], '#' . $ids[0] . ' (2 audits)' ), 'And links each issue' );
		$csv = ( new MLT\SchemaAudit\Export\Exporter( $runs[2] ) )->csv( 'summary' );
		icheck( false !== strpos( $csv, '"Findings: Unavailable in 2 or more audits in a row","' . count( $ids ) . '"' ), 'Export summary carries it: ' . substr( $csv, 0, 0 ) );
		icheck( false !== strpos( $csv, '"Findings: unavailable in a row, issue IDs","' . implode( ' ', $two['repeat_unavailable']['ids'] ) . '"' ), 'With the issue IDs' );

		// Read again: the figure drops to zero.
		$rid = Scheduler::start_recheck( $admin, array( $hostile_url ) );
		( new Worker() )->process( $rid, 60 );
		$three = Repository::decode( $repo->get_run( $rid )['summary'] );
		icheck( 0 === (int) $three['repeat_unavailable']['issues'] && array() === (array) $three['unavailable_streaks'], 'Page read again: nothing unavailable: ' . wp_json_encode( $three['repeat_unavailable'] ) );
		$wpdb->query( $wpdb->prepare( "UPDATE {$wpdb->prefix}mltsa_issues SET work_status = 'open' WHERE id = %d", $ids[0] ) );
		finish_active_runs();
		reset_settings();
	}
);

itest(
	'Review open check (fix 4): a worker killed while saving the frozen URL list does not insert URLs twice',
	static function () use ( $admin, $hostile_url ) {
		global $wpdb;
		$repo  = new Repository();
		$table = Installer::table( 'run_urls' );
		$urls  = array( home_url( '/' ), $hostile_url, home_url( '/?p=1' ) );
		foreach ( array( 'after the list was saved' => 'phase', 'part way through the list' => 'insert' ) as $label => $where ) {
			finish_active_runs();
			reset_settings();
			$id      = Scheduler::start_recheck( $admin, $urls );
			$inserts = 0;
			$kill    = static function ( $query ) use ( $where, $table, $id, &$inserts ) {
				if ( 'insert' === $where && 0 === stripos( ltrim( $query ), 'INSERT INTO `' . $table . '`' ) && 2 === ++$inserts ) {
					throw new RuntimeException( 'worker killed' );
				}
				if ( 'phase' === $where && false !== strpos( $query, "`phase` = 'fetch'" ) && preg_match( "/`id` = '?{$id}'?( |\$)/", $query ) ) {
					throw new RuntimeException( 'worker killed' );
				}
				return $query;
			};
			add_filter( 'query', $kill );
			$killed = false;
			try {
				( new Worker() )->process( $id, 60 );
			} catch ( RuntimeException $e ) {
				$killed = true;
			} finally {
				remove_filter( 'query', $kill );
			}
			icheck( $killed, "Worker killed {$label}" );
			// A killed PHP process loses its connection, and with it any open transaction.
			$wpdb->query( 'ROLLBACK' );
			icheck( 'discover' === $repo->get_run( $id )['phase'], 'Still in discovery' );
			$wpdb->query( $wpdb->prepare( "UPDATE {$wpdb->prefix}mltsa_runs SET lock_token = '', lock_expires = 0 WHERE id = %d", $id ) );
			( new Worker() )->process( $id, 60 );
			$rows = $wpdb->get_results( $wpdb->prepare( "SELECT seq, url_key FROM {$table} WHERE run_id = %d ORDER BY seq", $id ), ARRAY_A );
			icheck( 3 === count( $rows ), "Killed {$label}: three URLs, once each, not " . count( $rows ) );
			icheck( 3 === count( array_unique( array_column( $rows, 'url_key' ) ) ), 'No URL twice' );
			icheck( array( '1', '2', '3' ) === array_map( 'strval', array_column( $rows, 'seq' ) ), 'Sequence 1 to 3' );
			$run = $repo->get_run( $id );
			icheck( 'complete' === $run['state'] && 3 === (int) $run['done_count'], 'Run finished with each page read once: ' . $run['state'] . ' ' . $run['done_count'] );
		}
		finish_active_runs();
	}
);

itest(
	'Review open check (fix 6): a recheck started from the register through admin-post fetches the stored ?page_id= URL, not the home page',
	static function () use ( $admin, $hostile_post ) {
		global $wpdb;
		$repo      = new Repository();
		global $wp_rewrite;
		$permalink = get_option( 'permalink_structure' );
		$wp_rewrite->set_permalink_structure( '' );
		try {
			finish_active_runs();
			reset_settings();
			$plain = get_permalink( $hostile_post );
			icheck( false !== strpos( $plain, '?page_id=' . $hostile_post ), 'Plain permalink: ' . $plain );
			// Seed the register with issues stored against the plain permalink.
			$seed = Scheduler::start_recheck( $admin, array( $plain ) );
			( new Worker() )->process( $seed, 60 );
			$issue_ids = array_map( 'intval', $wpdb->get_col( $wpdb->prepare( "SELECT id FROM {$wpdb->prefix}mltsa_issues WHERE page_url = %s", $plain ) ) );
			icheck( count( $issue_ids ) > 0, 'Issues stored with the query string in page_url' );

			// The staff path: tick an issue, Recheck.
			list( $cookie, $nonce ) = session_for( $admin );
			$before = (int) $wpdb->get_var( "SELECT MAX(id) FROM {$wpdb->prefix}mltsa_runs" );
			$r      = http( 'POST', '/wp-admin/admin-post.php', $cookie, array( 'action' => 'mltsa_recheck', '_wpnonce' => $nonce['mltsa_recheck'], 'issue_ids' => array( $issue_ids[0] ) ) );
			icheck( 302 === $r['status'] && false !== strpos( $r['headers'], 'recheck_started' ), 'Recheck started through admin-post: ' . $r['status'] );
			$run_id = (int) $wpdb->get_var( "SELECT MAX(id) FROM {$wpdb->prefix}mltsa_runs" );
			icheck( $run_id > $before && 'recheck' === $repo->get_run( $run_id )['run_type'], 'A new recheck run' );
			( new Worker() )->process( $run_id, 60 );
			$row = $wpdb->get_row( $wpdb->prepare( 'SELECT url, final_url, http_status, coverage FROM ' . Installer::table( 'run_urls' ) . ' WHERE run_id = %d', $run_id ), ARRAY_A );
			icheck( $plain === $row['url'], 'Frozen URL keeps the query: ' . $row['url'] );
			icheck( 200 === (int) $row['http_status'] && 'ok' === $row['coverage'], 'Read: ' . wp_json_encode( $row ) );
			$observed = $wpdb->get_col( $wpdb->prepare( "SELECT observed FROM {$wpdb->prefix}mltsa_occurrences WHERE run_id = %d", $run_id ) );
			icheck( in_array( "+44 1632 960999' OR '1'='1", $observed, true ), 'The page served is the fixture page (its markup), not the home page' );
			icheck( 'complete' === $repo->get_run( $run_id )['state'], 'Recheck complete' );
			echo '      evidence: run ' . $run_id . ' fetched ' . $row['url'] . ' -> HTTP ' . $row['http_status'] . ', ' . count( $observed ) . " findings from the fixture page\n";
		} finally {
			$wp_rewrite->set_permalink_structure( $permalink );
			finish_active_runs();
		}
	}
);

itest(
	'Branch review R2: a site-wide issue resting on an unpublished page is cleared by a full audit; one resting on a page outside the post types, or a sitemap-only URL, is not',
	static function () use ( $admin ) {
		global $wpdb;
		finish_active_runs();
		reset_settings( array( 'post_types' => array( 'page' ), 'sitemap_discovery' => false, 'timeout' => 15 ) );
		$repo  = new Repository();
		$table = Installer::table( 'issues' );
		$about = wp_insert_post( array( 'post_type' => 'page', 'post_status' => 'publish', 'post_title' => 'R2 about', 'post_name' => 'r2-about', 'post_content' => 'x' ) );
		$dup   = wp_insert_post( array( 'post_type' => 'page', 'post_status' => 'publish', 'post_title' => 'R2 duplicate', 'post_name' => 'r2-old-duplicate', 'post_content' => 'x' ) );
		$news  = wp_insert_post( array( 'post_type' => 'post', 'post_status' => 'publish', 'post_title' => 'R2 news', 'post_name' => 'r2-news', 'post_content' => 'x' ) );
		$moved = wp_insert_post( array( 'post_type' => 'page', 'post_status' => 'publish', 'post_title' => 'S4 moved', 'post_name' => 's4-moved', 'post_content' => 'x' ) );
		$heir  = 0;
		$key   = static function ( $id ) {
			return Evaluator::url_key( get_permalink( $id ) );
		};
		$refs_dup  = array( $key( $about ), $key( $dup ) );
		$refs_news = array( $key( $about ), $key( $news ) );
		$refs_move = array( $key( $about ), $key( $moved ) );
		// Listed only by a sitemap in the past; sitemap discovery is now off.
		$refs_map  = array( $key( $about ), Evaluator::url_key( home_url( '/r2-sitemap-only/' ) ) );
		$version = Rules::fingerprint()['SITE-001'];
		$make    = static function ( $tag, array $refs ) use ( $repo, $version ) {
			return $repo->insert_issue(
				array(
					'issue_key'          => sha1( 'mltsa-r2-' . $tag ),
					'page_url'           => '',
					'site_wide'          => 1,
					'rule_id'            => 'SITE-001',
					'rule_version'       => $version,
					'severity'           => 'high',
					'entity_key'         => 'org',
					'first_observed_utc' => '2026-10-01 10:00:00',
					'last_observed_utc'  => '2026-10-01 10:00:00',
					'verification_state' => 'present',
					'work_status'        => 'open',
					'observed_hash'      => 'r2',
					'evidence'           => (string) wp_json_encode( $refs ),
				)
			);
		};
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$table} WHERE issue_key IN (%s, %s, %s, %s)", sha1( 'mltsa-r2-dup' ), sha1( 'mltsa-r2-news' ), sha1( 'mltsa-r2-map' ), sha1( 'mltsa-s4-move' ) ) );
		$client  = new class() implements MLT\SchemaAudit\Engine\HttpClient {
			public function request( $url, $pinned_ip, array $args ) {
				return array( 'status' => 200, 'error_code' => '', 'error' => '', 'headers' => array( 'content-type' => 'text/html' ), 'body' => '<html><head><title>x</title></head><body></body></html>', 'truncated' => false, 'pinned' => true );
			}
		};
		$audit  = static function () use ( $admin, $client, $repo ) {
			$run_id = Scheduler::start_manual( $admin );
			icheck( $run_id > 0, 'Full audit started' );
			for ( $i = 0; $i < 20; $i++ ) {
				$status = ( new Worker( $client, static function () {} ) )->process( $run_id, 60 );
				if ( ! in_array( $status['state'], array( 'queued', 'running' ), true ) ) {
					break;
				}
			}
			$run = $repo->get_run( $run_id );
			icheck( 'complete' === $run['state'], 'Audit complete: ' . $run['state'] );
		};
		try {
			// First audit while the duplicate page is published, so the
			// run history knows it as a post; then it is unpublished.
			$audit();
			wp_update_post( array( 'ID' => $dup, 'post_status' => 'draft' ) );
			// Branch review S4: the page is deleted and a post, a type outside
			// the audit settings, now has the same permalink.
			wp_delete_post( $moved, true );
			$heir = wp_insert_post( array( 'post_type' => 'post', 'post_status' => 'publish', 'post_title' => 'S4 heir', 'post_name' => 's4-moved', 'post_content' => 'x' ) );
			icheck( $key( $heir ) === $refs_move[1], 'The post has the deleted page\'s URL: ' . $key( $heir ) );
			$id_move = $make( 's4-move', $refs_move );
			$id_dup  = $make( 'dup', $refs_dup );
			$id_news = $make( 'news', $refs_news );
			$id_map  = $make( 'map', $refs_map );
			$audit();
			$state = static function ( $id ) use ( $wpdb, $table ) {
				return $wpdb->get_var( $wpdb->prepare( "SELECT verification_state FROM {$table} WHERE id = %d", $id ) );
			};
			icheck( 'no_longer_detected' === $state( $id_dup ), 'Evidence page unpublished, the other read: cleared, ' . $state( $id_dup ) );
			icheck( 'unavailable' === $state( $id_news ), 'Evidence page still published but outside the post types: held as unavailable, ' . $state( $id_news ) );
			icheck( 'unavailable' === $state( $id_move ), 'Evidence page deleted but its URL now served by a post outside the post types: held, ' . $state( $id_move ) );
			icheck( 'unavailable' === $state( $id_map ), 'Sitemap-only evidence URL, sitemap discovery off: held as unavailable, ' . $state( $id_map ) );
			$why = (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM ' . Installer::table( 'events' ) . " WHERE event_type = 'held_outside_scope' AND object_id IN (%d, %d)", $id_news, $id_map ) );
			icheck( 2 === $why, 'Each has an event saying why it is held: ' . $why );
			$last = $repo->runs( 1 )[0];
			$sum  = Repository::decode( $last['summary'] );
			icheck( isset( $sum['unavailable_streaks'][ $id_news ], $sum['unavailable_streaks'][ $id_map ] ), 'Both feed the repeated-unavailable figure: ' . wp_json_encode( isset( $sum['unavailable_streaks'] ) ? $sum['unavailable_streaks'] : null ) );
		} finally {
			finish_active_runs();
			wp_delete_post( $about, true );
			wp_delete_post( $dup, true );
			wp_delete_post( $news, true );
			wp_delete_post( $moved, true );
			if ( $heir ) {
				wp_delete_post( $heir, true );
			}
			$wpdb->query( $wpdb->prepare( "DELETE FROM {$table} WHERE issue_key IN (%s, %s, %s, %s)", sha1( 'mltsa-r2-dup' ), sha1( 'mltsa-r2-news' ), sha1( 'mltsa-r2-map' ), sha1( 'mltsa-s4-move' ) ) );
		}
	}
);

itest(
	'Branch review R3: a real HEAD of a static file over the size cap is ok, not too large; a GET of it still is',
	static function () use ( $admin ) {
		$dir  = wp_upload_dir()['basedir'];
		$file = $dir . '/mltsa-r3-brochure.pdf';
		wp_mkdir_p( $dir );
		file_put_contents( $file, str_repeat( 'a', 6000000 ) );
		try {
			$url     = content_url( '/uploads/mltsa-r3-brochure.pdf' );
			$policy  = new MLT\SchemaAudit\Engine\UrlPolicy( home_url( '/' ), true );
			$fetcher = new MLT\SchemaAudit\Engine\Fetcher( $policy, new MLT\SchemaAudit\Engine\WpHttpClient(), array( 'timeout' => 20, 'user_agent' => 'mltsa-test' ), static function () {} );
			$head    = $fetcher->fetch( $url, 'HEAD', true );
			icheck( 'ok' === $head['outcome'] && 200 === (int) $head['status'], 'HEAD: ' . $head['outcome'] . ' ' . $head['status'] . ' ' . $head['reason'] );
			icheck( 6000000 === (int) $head['headers']['content-length'], 'Server sent the file size: ' . $head['headers']['content-length'] );
			$get = $fetcher->fetch( $url, 'GET', true );
			icheck( 'too_large' === $get['outcome'], 'GET body over the cap: ' . $get['outcome'] );
		} finally {
			unlink( $file );
		}

		// A server that refuses HEAD: the GET fallback's 2xx shows the file
		// exists, so its body size does not hold the check.
		finish_active_runs();
		reset_settings( array( 'timeout' => 15 ) );
		$repo  = new Repository();
		$id    = Scheduler::start_recheck( $admin, array( home_url( '/' ) ) );
		$image = home_url( '/wp-content/uploads/r3-big-logo.png' );
		$repo->update_run( $id, array( 'state' => 'running', 'phase' => 'resources', 'summary' => (string) wp_json_encode( array( 'resources' => array( $image => array( array( 'url_id' => 0, 'prop' => 'logo', 'path' => "$['logo']", 'block' => 0 ) ) ) ) ) ) );
		$client = new class() implements MLT\SchemaAudit\Engine\HttpClient {
			public function request( $url, $pinned_ip, array $args ) {
				if ( 'HEAD' === $args['method'] ) {
					return array( 'status' => 405, 'error_code' => '', 'error' => '', 'headers' => array(), 'body' => '', 'truncated' => false, 'pinned' => true );
				}
				return array( 'status' => 200, 'error_code' => '', 'error' => '', 'headers' => array( 'content-type' => 'image/png', 'content-length' => '9000000' ), 'body' => str_repeat( 'a', 100 ), 'truncated' => true, 'pinned' => true );
			}
		};
		$written = '';
		$capture = static function ( $query ) use ( &$written ) {
			if ( false !== strpos( $query, 'resource_outcomes' ) && false === strpos( $query, 'resource_attempts' ) ) {
				$written = $query;
			}
			return $query;
		};
		add_filter( 'query', $capture );
		( new Worker( $client, static function () {} ) )->process( $id, 5 );
		remove_filter( 'query', $capture );
		icheck( false !== strpos( stripslashes( $written ), 'r3-big-logo.png":"ok"' ), 'GET fallback 200 over the cap recorded as ok: ' . substr( $written, 0, 300 ) );
		finish_active_runs();
	}
);

itest(
	'Branch review R4: a cancel during reconcile rolls the step back, so a cancelled run leaves the register unchanged; a killed reconcile leaves nothing half written',
	static function () use ( $admin ) {
		global $wpdb;
		$repo   = new Repository();
		$issues = Installer::table( 'issues' );
		$events = Installer::table( 'events' );
		$occ    = Installer::table( 'occurrences' );
		$client = new class() implements MLT\SchemaAudit\Engine\HttpClient {
			public function request( $url, $pinned_ip, array $args ) {
				// FACT-001 style finding: an Organization with no name, so the
				// recheck has a page issue to reconcile.
				return array( 'status' => 200, 'error_code' => '', 'error' => '', 'headers' => array( 'content-type' => 'text/html' ), 'body' => '<html><head><script type="application/ld+json">{"@context":"https://schema.org","@type":"LegalService","telephone":"01632 960123"}</script></head><body></body></html>', 'truncated' => false, 'pinned' => true );
			}
		};
		$snapshot = static function ( $id ) use ( $wpdb, $issues, $events, $occ ) {
			return array(
				'issues' => md5( serialize( $wpdb->get_results( "SELECT * FROM {$issues} ORDER BY id", ARRAY_N ) ) ),
				'events' => (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$events} WHERE run_id = %d", $id ) ),
				'linked' => (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$occ} WHERE run_id = %d AND issue_id > 0", $id ) ),
			);
		};
		// Run to the reconcile step.
		$to_reconcile = static function () use ( $admin, $repo, $client ) {
			finish_active_runs();
			reset_settings( array( 'timeout' => 15 ) );
			$id = Scheduler::start_recheck( $admin, array( home_url( '/r4-reconcile-test/' ) ) );
			$repo->update_run( $id, array( 'state' => 'running' ) );
			for ( $i = 0; $i < 10 && 'reconcile' !== $repo->get_run( $id )['phase']; $i++ ) {
				$w    = new Worker( $client, static function () {} );
				$step = new ReflectionMethod( $w, 'step' );
				$step->setAccessible( true );
				$step->invoke( $w, $repo->get_run( $id ), microtime( true ) + 60 );
			}
			return $id;
		};

		// 1. A cancel from another connection (the audit screen) arrives
		// after reconcile has started.
		$id = $to_reconcile();
		icheck( 'reconcile' === $repo->get_run( $id )['phase'], 'Run reached reconcile' );
		$occurrences = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$occ} WHERE run_id = %d", $id ) );
		icheck( $occurrences > 0, 'The page has findings to reconcile: ' . $occurrences );
		$before = $snapshot( $id );
		$fired  = false;
		$is_register_write = static function ( $query ) use ( $issues, $occ ) {
			return (bool) preg_match( '/^\s*(INSERT INTO|UPDATE)\s+`?(' . preg_quote( $issues, '/' ) . '|' . preg_quote( $occ, '/' ) . ')`?\s/', $query );
		};
		$hook   = static function ( $query ) use ( $id, $is_register_write, &$fired ) {
			if ( ! $fired && $is_register_write( $query ) ) {
				$fired = true;
				$other = new PDO( 'sqlite:' . FQDB, null, null, array( PDO::ATTR_TIMEOUT => 2 ) );
				$other->exec( "UPDATE " . Installer::table( 'runs' ) . " SET state = 'cancelled', phase = 'done' WHERE id = " . (int) $id . " AND state IN ('queued','running') AND phase <> 'notify'" );
				$other = null;
			}
			return $query;
		};
		add_filter( 'query', $hook );
		try {
			( new Worker( $client, static function () {} ) )->process( $id, 60 );
		} finally {
			remove_filter( 'query', $hook );
		}
		$run = $repo->get_run( $id );
		icheck( $fired, 'The cancel landed during the register writes' );
		icheck( 'cancelled' === $run['state'] && 'done' === $run['phase'], 'Run stays cancelled: ' . $run['state'] . '/' . $run['phase'] );
		icheck( $before === $snapshot( $id ), 'Register unchanged by the cancelled run: ' . wp_json_encode( array( $before, $snapshot( $id ) ) ) );

		// 2. A worker killed part way through reconcile: nothing half
		// written; the next slice reconciles once.
		$id     = $to_reconcile();
		$before = $snapshot( $id );
		$writes = 0;
		$die    = static function ( $query ) use ( $is_register_write, &$writes ) {
			// Let the first register write through, then kill the worker.
			if ( $is_register_write( $query ) && ++$writes >= 2 ) {
				throw new RuntimeException( 'killed in reconcile' );
			}
			return $query;
		};
		add_filter( 'query', $die );
		try {
			( new Worker( $client, static function () {} ) )->process( $id, 60 );
			icheck( false, 'The worker should have died' );
		} catch ( RuntimeException $e ) {
			icheck( 'killed in reconcile' === $e->getMessage(), 'Died in reconcile' );
		} finally {
			remove_filter( 'query', $die );
		}
		icheck( $before === $snapshot( $id ), 'Nothing written by the killed step: ' . wp_json_encode( array( $before, $snapshot( $id ) ) ) );
		$repo->update_run( $id, array( 'lock_token' => '' ) );
		( new Worker( $client, static function () {} ) )->process( $id, 60 );
		$run = $repo->get_run( $id );
		icheck( 'complete' === $run['state'], 'Retry completes: ' . $run['state'] );
		$after = $snapshot( $id );
		icheck( $after['linked'] > 0 && $before['issues'] !== $after['issues'], 'Register written once by the retry: ' . wp_json_encode( $after ) );

		// 3. The kill switch reaching a monthly run that has written the
		// register: it finishes, and the outbox holds its mail.
		finish_active_runs();
		$mid = $repo->create_run( array( 'run_type' => 'monthly', 'trigger_type' => 'system', 'schedule_key' => 'r4-' . wp_generate_password( 8, false ), 'state' => 'running', 'phase' => 'notify', 'url_count' => 1, 'summary' => (string) wp_json_encode( array( 'findings' => 0 ) ) ) );
		Settings::update( array( 'kill_switch' => true ), $admin );
		try {
			( new Worker( $client, static function () {} ) )->process( $mid, 60 );
		} finally {
			Settings::update( array( 'kill_switch' => false ), $admin );
		}
		$run = $repo->get_run( $mid );
		icheck( 'cancelled' !== $run['state'] && 'done' === $run['phase'], 'Kill switch after reconcile: run finishes, ' . $run['state'] . '/' . $run['phase'] );
		finish_active_runs();
	}
);

itest(
	'Branch review R5: while the database upgrade has not completed, audits neither start nor run, and the screens and WP-CLI say why',
	static function () use ( $admin ) {
		global $wpdb;
		finish_active_runs();
		reset_settings();
		$repo    = new Repository();
		$version = get_option( 'mltsa_db_version' );
		$runs    = $repo->count_runs();
		// The server process would retry the upgrade on boot; hold it off.
		set_transient( 'mltsa_upgrade_retry', 1, 600 );
		update_option( 'mltsa_db_version', '1', false );
		try {
			icheck( MLT\SchemaAudit\Installer::upgrade_pending(), 'Upgrade pending' );
			icheck( 0 === Scheduler::start_manual( $admin ), 'Manual start refused' );
			icheck( 0 === Scheduler::start_recheck( $admin, array( home_url( '/' ) ) ), 'Recheck refused' );
			icheck( $repo->count_runs() === $runs, 'No run created' );

			$health = '';
			foreach ( MLT\SchemaAudit\Admin\Health::checks() as $check ) {
				if ( 'Database upgrade' === $check['label'] ) {
					$health = $check['status'] . ': ' . $check['detail'];
				}
			}
			icheck( 0 === strpos( $health, 'fail: ' ) && false !== strpos( $health, 'Audits do not start or run' ), 'Health: ' . $health );

			list( $cookie, $nonce ) = session_for( $admin );
			$r = http( 'GET', '/wp-admin/admin.php?page=mltsa', $cookie );
			icheck( 200 === $r['status'] && false !== strpos( $r['body'], 'the upgrade did not complete' ) && false === strpos( $r['body'], 'value="mltsa_start"' ), 'Audit screen gives the reason and no Start button: ' . $r['status'] );
			$r = http( 'POST', '/wp-admin/admin-post.php', $cookie, array( 'action' => 'mltsa_start', '_wpnonce' => $nonce['mltsa_start'] ) );
			icheck( 302 === $r['status'] && false !== strpos( $r['headers'], 'schema_outdated' ), 'Start through admin-post refused with the reason: ' . $r['status'] );
			icheck( $repo->count_runs() === $runs, 'Still no run created' );

			$wp   = escapeshellarg( ABSPATH );
			$cmd  = 'php -d error_reporting=24575 ' . escapeshellarg( trim( (string) shell_exec( 'command -v wp' ) ) ) . ' --path=' . $wp;
			$out  = (string) shell_exec( $cmd . ' mltsa audit 2>&1' );
			icheck( false !== strpos( $out, 'Refused' ) && false !== strpos( $out, 'the upgrade did not complete' ), 'wp mltsa audit refused with the reason: ' . trim( $out ) );

			// A run already in progress when the upgrade failed is not worked on.
			$id     = $repo->create_run( array( 'run_type' => 'manual', 'trigger_type' => 'user', 'state' => 'running', 'phase' => 'fetch', 'scope' => (string) wp_json_encode( array( 'urls' => array( home_url( '/' ) ) ) ) ) );
			$client = timing_out_client();
			$status = ( new Worker( $client, static function () {} ) )->process( $id, 5 );
			icheck( 'schema_outdated' === $status['note'] && 0 === $client->count, 'Worker does nothing: ' . wp_json_encode( $status ) );
			icheck( 'fetch' === $repo->get_run( $id )['phase'], 'Run left where it was' );
			$r = http( 'POST', '/wp-admin/admin-ajax.php', $cookie, array( 'action' => 'mltsa_step', 'nonce' => $nonce['mltsa_step'] ) );
			icheck( false !== strpos( $r['body'], '"state":"schema_outdated"' ) && false !== strpos( $r['body'], 'the upgrade did not complete' ), 'Audit screen step stops with the reason: ' . substr( $r['body'], 0, 200 ) );
			$tick = (string) shell_exec( $cmd . ' mltsa tick --budget=5 2>&1' );
			icheck( false !== strpos( $tick, 'Warning' ) && false !== strpos( $tick, 'schema_outdated' ), 'wp mltsa tick warns and does no work: ' . trim( $tick ) );
			icheck( 'fetch' === $repo->get_run( $id )['phase'], 'Still left where it was' );
		} finally {
			update_option( 'mltsa_db_version', $version, false );
			delete_transient( 'mltsa_upgrade_retry' );
			finish_active_runs();
		}
		icheck( ! MLT\SchemaAudit\Installer::upgrade_pending(), 'Version restored' );
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
