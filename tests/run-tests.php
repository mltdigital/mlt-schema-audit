<?php
/**
 * Unit test runner. Usage: php tests/run-tests.php [filter]
 *
 * Each test name starts with the acceptance case, threat ID or fixture ID it
 * proves, so a failure points straight at the requirement it breaks.
 *
 * @package MLT\SchemaAudit
 */

// phpcs:disable

require __DIR__ . '/bootstrap.php';

foreach ( glob( __DIR__ . '/unit/*.php' ) as $file ) {
	require $file;
}

$filter = isset( $argv[1] ) ? $argv[1] : '';
$passed = 0;
foreach ( $GLOBALS['mltsa_tests'] as $name => $fn ) {
	if ( '' !== $filter && false === stripos( $name, $filter ) ) {
		continue;
	}
	try {
		$fn();
		++$passed;
	} catch ( Throwable $e ) {
		$GLOBALS['mltsa_failures'][ $name ] = $e->getMessage() . ' at ' . basename( $e->getFile() ) . ':' . $e->getLine();
	}
}

foreach ( $GLOBALS['mltsa_failures'] as $name => $message ) {
	echo "FAIL  {$name}\n      {$message}\n";
}
$failed = count( $GLOBALS['mltsa_failures'] );
printf( "%d passed, %d failed, %d assertions\n", $passed, $failed, $GLOBALS['mltsa_asserts'] );
exit( $failed > 0 ? 1 : 0 );
