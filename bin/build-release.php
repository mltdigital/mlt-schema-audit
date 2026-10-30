<?php
/**
 * Build the release ZIP from an explicit allowlist (threat R1).
 *
 *   php bin/build-release.php            build dist/mlt-schema-audit-<version>.zip and .sha256
 *   php bin/build-release.php --check    verify an existing build against the allowlist
 *
 * Only files tracked by git and matched by the allowlist are packed, so
 * client evidence, fixtures, tests, development tools and anything
 * untracked can never ship. The build fails if an allowlisted file has
 * uncommitted changes, if versions disagree, if a file holds a client name
 * or a development switch, or if the finished ZIP holds anything outside
 * the allowlist. Entry dates come from the last commit, so the same commit
 * always gives the same bytes and the same checksum.
 *
 * @package MLT\SchemaAudit
 */

// phpcs:disable

define( 'MLTSA_TESTING', true ); // Loads the pure ZipStream class outside WordPress.
require dirname( __DIR__ ) . '/includes/Export/ZipStream.php';

const ALLOWLIST = array(
	'#^mlt-schema-audit\.php$#',
	'#^uninstall\.php$#',
	'#^includes/[A-Za-z]+(/[A-Za-z]+)*\.php$#',
	'#^assets/admin\.(js|css)$#',
	'#^CHANGELOG\.md$#',
);
const BANNED = '/define\(\s*[\'"]MLTSA_ALLOW_PRIVATE_SELF/i';
require dirname( __DIR__ ) . '/tests/support/client-names.php';

$root = dirname( __DIR__ );
chdir( $root );

function fail( $message ) {
	fwrite( STDERR, "BUILD FAILED: {$message}\n" );
	exit( 1 );
}
function allowed( $path ) {
	foreach ( ALLOWLIST as $pattern ) {
		if ( preg_match( $pattern, $path ) ) {
			return true;
		}
	}
	return false;
}

$header  = file_get_contents( 'mlt-schema-audit.php' );
$version = preg_match( '/^\s*\*\s*Version:\s*([0-9.]+)/m', $header, $m ) ? $m[1] : '';
$const   = preg_match( "/define\( 'MLTSA_VERSION', '([0-9.]+)' \)/", $header, $m ) ? $m[1] : '';
if ( '' === $version || $version !== $const ) {
	fail( "plugin header version ({$version}) and MLTSA_VERSION ({$const}) differ" );
}
if ( false === strpos( file_get_contents( 'CHANGELOG.md' ), '(' . $version . ')' ) && false === strpos( file_get_contents( 'CHANGELOG.md' ), '## ' . $version ) ) {
	fail( "CHANGELOG.md has no entry for {$version}" );
}

$tracked = array_filter( explode( "\n", (string) shell_exec( 'git ls-files' ) ) );
$files   = array_values( array_filter( $tracked, 'allowed' ) );
sort( $files );
if ( empty( $files ) ) {
	fail( 'no files matched the allowlist' );
}
$dirty = trim( (string) shell_exec( 'git status --porcelain -- ' . implode( ' ', array_map( 'escapeshellarg', $files ) ) ) );
if ( '' !== $dirty ) {
	fail( "allowlisted files have uncommitted changes:\n{$dirty}" );
}
foreach ( $files as $file ) {
	$text = file_get_contents( $file );
	if ( preg_match( BANNED, $text, $hit ) ) {
		fail( "{$file} contains \"{$hit[0]}\"" );
	}
	$name = mltsa_client_name_hit( $text );
	if ( '' !== $name ) {
		fail( "{$file} contains a client name (\"{$name}\")" );
	}
}

$name = "mlt-schema-audit-{$version}.zip";
$zip  = "{$root}/dist/{$name}";

if ( in_array( '--check', $argv, true ) ) {
	if ( ! is_file( $zip ) ) {
		fail( "{$zip} does not exist" );
	}
} else {
	@mkdir( "{$root}/dist", 0755 );
	$time  = (int) trim( (string) shell_exec( 'git log -1 --format=%ct' ) );
	$bytes = '';
	$out   = new MLT\SchemaAudit\Export\ZipStream(
		static function ( $chunk ) use ( &$bytes ) {
			$bytes .= $chunk;
		},
		$time ? $time : time()
	);
	foreach ( $files as $file ) {
		$out->add( 'mlt-schema-audit/' . $file, file_get_contents( $file ) );
	}
	$out->finish();
	file_put_contents( $zip, $bytes );
}

// Verify what was written: every entry allowlisted, every allowlisted file present.
$entries = array();
if ( class_exists( 'ZipArchive' ) ) {
	$z = new ZipArchive();
	if ( true !== $z->open( $zip, ZipArchive::CHECKCONS ) ) {
		fail( 'the ZIP does not open cleanly' );
	}
	for ( $i = 0; $i < $z->numFiles; $i++ ) {
		$entries[] = $z->getNameIndex( $i );
	}
	$z->close();
} else {
	$entries = array_filter( array_map( 'trim', explode( "\n", (string) shell_exec( 'unzip -Z1 ' . escapeshellarg( $zip ) ) ) ) );
}
foreach ( $entries as $entry ) {
	if ( 0 !== strpos( $entry, 'mlt-schema-audit/' ) || ! allowed( substr( $entry, strlen( 'mlt-schema-audit/' ) ) ) ) {
		fail( "the ZIP holds a file outside the allowlist: {$entry}" );
	}
}
$expected = array_map(
	static function ( $f ) {
		return 'mlt-schema-audit/' . $f;
	},
	$files
);
sort( $entries );
if ( $entries !== $expected ) {
	fail( 'the ZIP does not hold exactly the allowlisted files' );
}

$hash = hash_file( 'sha256', $zip );
file_put_contents( "{$zip}.sha256", "{$hash}  {$name}\n" );
printf( "%s\n%d files, %d bytes\nSHA-256 %s\n", $zip, count( $entries ), filesize( $zip ), $hash );
