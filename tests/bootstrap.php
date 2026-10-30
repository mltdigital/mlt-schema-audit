<?php
/**
 * Unit test bootstrap: no WordPress, no database, no network.
 *
 * Engine classes are pure PHP, so they run here directly. Classes that need
 * WordPress are covered by tests/integration/ against a disposable install.
 *
 * @package MLT\SchemaAudit
 */

// phpcs:disable

error_reporting( E_ALL );
ini_set( 'display_errors', '1' );

define( 'MLTSA_TESTING', true );
define( 'MLTSA_DIR', dirname( __DIR__ ) . '/' );

spl_autoload_register(
	static function ( $class ) {
		$prefix = 'MLT\\SchemaAudit\\';
		if ( 0 !== strpos( $class, $prefix ) ) {
			return;
		}
		$file = MLTSA_DIR . 'includes/' . str_replace( '\\', '/', substr( $class, strlen( $prefix ) ) ) . '.php';
		if ( is_file( $file ) ) {
			require $file;
		}
	}
);

$GLOBALS['mltsa_tests']    = array();
$GLOBALS['mltsa_failures'] = array();
$GLOBALS['mltsa_asserts']  = 0;

/**
 * Register a test.
 *
 * @param string   $name Name, prefixed with the acceptance case or threat ID it proves.
 * @param callable $fn   Test body.
 */
function mltsa_test( $name, $fn ) {
	$GLOBALS['mltsa_tests'][ $name ] = $fn;
}

/**
 * Assert a condition.
 *
 * @param bool   $condition Condition.
 * @param string $message   Message on failure.
 */
function check( $condition, $message ) {
	++$GLOBALS['mltsa_asserts'];
	if ( ! $condition ) {
		throw new RuntimeException( $message );
	}
}

/**
 * Assert equality.
 *
 * @param mixed  $expected Expected.
 * @param mixed  $actual   Actual.
 * @param string $message  Message.
 */
function check_same( $expected, $actual, $message ) {
	check( $expected === $actual, $message . ' (expected ' . var_export( $expected, true ) . ', got ' . var_export( $actual, true ) . ')' );
}

/**
 * Rule IDs in a findings list.
 *
 * @param array $findings Findings.
 * @return array
 */
function rule_ids( array $findings ) {
	$ids = array();
	foreach ( $findings as $f ) {
		$ids[] = $f['rule_id'];
	}
	sort( $ids );
	return array_values( array_unique( $ids ) );
}

/**
 * Audit a fixture page end to end through the engine (no fetch).
 *
 * @param string $html     HTML.
 * @param string $page_url Page URL.
 * @param array  $context  Context overrides.
 * @return array Evaluator output.
 */
function audit_html( $html, $page_url = 'https://www.example-legal.co.uk/', array $context = array() ) {
	$extractor = new MLT\SchemaAudit\Engine\Extractor();
	$evaluator = new MLT\SchemaAudit\Engine\Evaluator(
		array_merge(
			array(
				'page_url'    => $page_url,
				'own_hosts'   => array( 'www.example-legal.co.uk', 'example-legal.co.uk' ),
				'home_scheme' => 'https',
			),
			$context
		)
	);
	return $evaluator->evaluate( $extractor->extract( $html ) );
}

/**
 * Scripted HTTP client for fetcher tests.
 */
class Scripted_Client implements MLT\SchemaAudit\Engine\HttpClient {
	public $responses = array();
	public $requests  = array();
	public function request( $url, $pinned_ip, array $args ) {
		$this->requests[] = array( 'url' => $url, 'ip' => $pinned_ip, 'args' => $args );
		$r = isset( $this->responses[ $url ] ) ? $this->responses[ $url ] : array( 'status' => 404 );
		if ( is_callable( $r ) ) {
			$r = $r();
		}
		return array_merge( array( 'status' => 200, 'headers' => array( 'content-type' => 'text/html' ), 'body' => '', 'error' => '', 'error_code' => '', 'pinned' => true, 'truncated' => false ), $r );
	}
}
