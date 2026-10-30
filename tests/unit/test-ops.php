<?php
/**
 * Unit tests for the pure operations classes: calendar, digest, CSV, ZIP,
 * issue validation, retention selection and discovery.
 *
 * @package MLT\SchemaAudit
 */

// phpcs:disable

use MLT\SchemaAudit\Discovery;
use MLT\SchemaAudit\Engine\UrlPolicy;
use MLT\SchemaAudit\Export\Csv;
use MLT\SchemaAudit\Export\ZipStream;
use MLT\SchemaAudit\Issues;
use MLT\SchemaAudit\Ops\Calendar;
use MLT\SchemaAudit\Ops\Digest;
use MLT\SchemaAudit\Ops\Retention;

function cal( $ordinal, $weekday, $time = '09:00', $tz = 'Europe/London' ) {
	return array(
		'schedule_ordinal'  => $ordinal,
		'schedule_weekday'  => $weekday,
		'schedule_time'     => $time,
		'schedule_timezone' => $tz,
	);
}

mltsa_test(
	'AC schedule: first Monday 09:00 Europe/London, next three dates, in winter and summer time',
	static function () {
		$after = gmmktime( 12, 0, 0, 10, 30, 2026 );
		$next  = Calendar::next( cal( 'first', 'monday' ), $after, 3 );
		$fmt   = static function ( $ts ) {
			return ( new DateTimeImmutable( '@' . $ts ) )->setTimezone( new DateTimeZone( 'Europe/London' ) )->format( 'Y-m-d H:i T' );
		};
		check_same( array( '2026-11-02 09:00 GMT', '2026-12-07 09:00 GMT', '2027-01-04 09:00 GMT' ), array_map( $fmt, $next ), 'Next three' );
		$summer = Calendar::next( cal( 'first', 'monday' ), gmmktime( 0, 0, 0, 5, 1, 2027 ), 1 );
		check_same( '2027-05-03 09:00 BST', $fmt( $summer[0] ), 'Summer time start' );
		check_same( gmmktime( 8, 0, 0, 5, 3, 2027 ), $summer[0], 'BST is UTC+1' );
	}
);

mltsa_test(
	'AC schedule: second, third, fourth and last weekday, and the occurrence itself is not "next"',
	static function () {
		$fmt = static function ( $ts ) {
			return ( new DateTimeImmutable( '@' . $ts ) )->setTimezone( new DateTimeZone( 'Europe/London' ) )->format( 'Y-m-d' );
		};
		$from = gmmktime( 0, 0, 0, 11, 1, 2026 );
		check_same( '2026-11-10', $fmt( Calendar::next( cal( 'second', 'tuesday' ), $from )[0] ), 'Second Tuesday' );
		check_same( '2026-11-19', $fmt( Calendar::next( cal( 'third', 'thursday' ), $from )[0] ), 'Third Thursday' );
		check_same( '2026-11-27', $fmt( Calendar::next( cal( 'fourth', 'friday' ), $from )[0] ), 'Fourth Friday' );
		check_same( '2026-11-30', $fmt( Calendar::next( cal( 'last', 'monday' ), $from )[0] ), 'Last Monday' );
		$occ = Calendar::occurrence( 2026, 11, 'first', 'monday', '09:00', 'Europe/London' );
		check_same( '2026-12-07', $fmt( Calendar::next( cal( 'first', 'monday' ), $occ )[0] ), 'Strictly after' );
		check_same( $occ, Calendar::previous( cal( 'first', 'monday' ), $occ + 60 ), 'Previous occurrence' );
		check_same( 'monthly-2026-11', Calendar::schedule_key( $occ, 'Europe/London' ), 'Schedule key' );
	}
);

mltsa_test(
	'M1 the subject is built from host and date only, with control characters removed',
	static function () {
		$subject = Digest::subject( "evil.example\r\nBcc: victim@example.com", "2026-11-02\n", 'changes' );
		check( false === strpos( $subject, "\n" ) && false === strpos( $subject, "\r" ), 'No line breaks' );
		check( 1 === preg_match( '/^Schema audit for [a-z0-9.:\-]+, [0-9\-]+: [a-z ]+$/i', $subject ), 'One clean subject line: ' . $subject );
		check_same( array( 'Content-Type: text/plain; charset=UTF-8' ), Digest::headers(), 'Fixed headers' );
	}
);

mltsa_test(
	'M2 the email body carries counts and a link, never page titles, page URLs, evidence or notes',
	static function () {
		$body = Digest::body(
			array(
				'host'              => 'www.firm.example',
				'date'              => '2026-11-02',
				'type'              => 'changes',
				'state'             => 'complete',
				'pages_read'        => 10,
				'pages_total'       => 10,
				'pages_unavailable' => 0,
				'findings'          => 4,
				'comparison'        => array( 'new' => 2, 'resolved' => 1 ),
				'link'              => 'https://www.firm.example/wp-admin/admin.php?page=mltsa&run=7',
			)
		);
		check( false !== strpos( $body, 'New findings: 2' ) && false !== strpos( $body, 'No longer detected: 1' ), 'Counts present' );
		check( 1 === preg_match_all( '#https?://#', $body ), 'Only one URL, the authenticated link' );
		$alert = Digest::body( array( 'host' => 'h', 'date' => 'd', 'type' => 'alert', 'state' => 'partial', 'pages_read' => 5, 'pages_total' => 10, 'pages_unavailable' => 5, 'findings' => 0, 'link' => 'x' ) );
		check( false !== strpos( $alert, 'not an all-clear' ), 'A partial run is an operational alert' );
	}
);

mltsa_test(
	'M2 which notification a run needs: alerts for partial and failed runs, nothing when nothing changed',
	static function () {
		check_same( 'alert', Digest::type_for( array( 'state' => 'partial' ), array(), false ), 'Partial' );
		check_same( 'alert', Digest::type_for( array( 'state' => 'failed' ), array(), false ), 'Failed' );
		check_same( 'baseline', Digest::type_for( array( 'state' => 'complete' ), array( 'is_baseline' => true ), false ), 'Baseline' );
		check_same( 'changes', Digest::type_for( array( 'state' => 'complete' ), array( 'comparison' => array( 'meaningful' => true ) ), false ), 'Changes' );
		check_same( '', Digest::type_for( array( 'state' => 'complete' ), array( 'comparison' => array( 'meaningful' => false ) ), false ), 'No change, off by default' );
		check_same( 'no_change', Digest::type_for( array( 'state' => 'complete' ), array( 'comparison' => array( 'meaningful' => false ) ), true ), 'No change when switched on' );
	}
);

mltsa_test(
	'E1 cells starting with =, +, -, @, tab or carriage return are neutralised; zeros, line breaks and UK text survive',
	static function () {
		foreach ( array( '=1+1', '+44 1632', '-2', '@SUM(A1)', "\tx", "\rx" ) as $value ) {
			check_same( "'" . $value, Csv::cell( $value ), 'Neutralised ' . json_encode( $value ) );
		}
		check_same( '01632 960000', Csv::cell( '01632 960000' ), 'Leading zero kept' );
		check_same( "\"a \"\"b\"\"\",\"line1\nline2\",\"£ é ’\"\r\n", Csv::line( array( 'a "b"', "line1\nline2", '£ é ’' ) ), 'Quoted, line breaks and UK characters kept' );
		check( 0 === strpos( Csv::document( array( 'h' ), array() ), "\xEF\xBB\xBF" ), 'UTF-8 byte-order mark' );
	}
);

mltsa_test(
	'E2 the ZIP is built in memory and opens with the expected files and contents',
	static function () {
		$bytes = '';
		$zip   = new ZipStream(
			static function ( $chunk ) use ( &$bytes ) {
				$bytes .= $chunk;
			},
			gmmktime( 10, 0, 0, 10, 30, 2026 )
		);
		$zip->add( 'summary.csv', "\xEF\xBB\xBF\"Item\",\"Value\"\r\n" );
		$zip->add( 'manifest.json', str_repeat( '{"run_id":1}', 500 ) );
		$zip->finish();
		check( 0 === strpos( $bytes, "PK\x03\x04" ), 'Local header first' );
		if ( class_exists( 'ZipArchive' ) ) {
			$tmp = tempnam( sys_get_temp_dir(), 'mltsa' );
			file_put_contents( $tmp, $bytes );
			$z = new ZipArchive();
			check( true === $z->open( $tmp, ZipArchive::CHECKCONS ), 'Archive is consistent' );
			check_same( 2, $z->numFiles, 'Two entries' );
			check_same( str_repeat( '{"run_id":1}', 500 ), $z->getFromName( 'manifest.json' ), 'Contents round-trip' );
			$z->close();
			unlink( $tmp );
		}
	}
);

mltsa_test(
	'AC statuses: exceptions and false positives need a reason, reviewer and review date; dates and links validated',
	static function () {
		$issue = array( 'work_status' => 'open', 'exception_reason' => '', 'exception_reviewer' => '', 'exception_review_date' => null, 'owner_user_id' => 0, 'due_date' => null, 'external_link' => '' );
		$r     = Issues::validate( $issue, array( 'work_status' => 'false_positive' ) );
		check( ! empty( $r['errors'] ) && empty( $r['fields'] ), 'Rejected without a reason' );
		$r = Issues::validate( $issue, array( 'work_status' => 'accepted_exception', 'exception_reason' => 'Client confirmed', 'exception_reviewer' => 'MLT', 'exception_review_date' => '2026-02-30' ) );
		check( ! empty( $r['errors'] ), 'Impossible date rejected' );
		$r = Issues::validate( $issue, array( 'work_status' => 'accepted_exception', 'exception_reason' => 'Client confirmed', 'exception_reviewer' => 'MLT', 'exception_review_date' => '2026-11-30' ) );
		check( empty( $r['errors'] ) && 'accepted_exception' === $r['fields']['work_status'], 'Accepted with all three' );
		check( ! empty( Issues::validate( $issue, array( 'work_status' => 'verified' ) )['errors'] ), 'Unknown status rejected' );
		check( ! empty( Issues::validate( $issue, array( 'external_link' => 'javascript:alert(1)' ) )['errors'] ), 'Non-https link rejected' );
		check( ! empty( Issues::validate( $issue, array( 'work_status' => 'no_longer_detected' ) )['errors'] ), 'A verification state cannot be set as a work status' );
	}
);

mltsa_test(
	'D1 retention keeps the newest monthly and other runs, the next baseline and open-finding evidence',
	static function () {
		$runs = array();
		for ( $i = 30; $i >= 1; $i-- ) {
			$runs[] = array( 'id' => $i, 'run_type' => 0 === $i % 3 ? 'manual' : 'monthly', 'state' => 'complete' );
		}
		$purge = Retention::select( $runs, 13, array( 2 ) );
		$kept_monthly = array();
		foreach ( $runs as $run ) {
			if ( 'monthly' === $run['run_type'] && ! in_array( $run['id'], $purge, true ) ) {
				$kept_monthly[] = $run['id'];
			}
		}
		check( count( $kept_monthly ) >= 13, 'At least 13 monthly runs kept' );
		check( ! in_array( 29, $purge, true ), 'Newest monthly (the next baseline) kept' );
		check( ! in_array( 2, $purge, true ), 'Run holding open-finding evidence kept' );
		check( in_array( 1, $purge, true ), 'Oldest unprotected monthly purged' );
		check_same( array(), Retention::select( array_slice( $runs, 0, 10 ), 13, array() ), 'Nothing purged below the limit' );
	}
);

mltsa_test(
	'F6 discovery drops query strings from sitemaps and excludes admin, login, XML-RPC and REST URLs with a reason',
	static function () {
		$policy = new UrlPolicy( 'https://www.firm.example/', false, static function () {
			return array( '203.0.113.10' );
		} );
		$xml    = '<?xml version="1.0"?><urlset><url><loc>https://www.firm.example/about/?utm=1</loc></url><url><loc>https://www.firm.example/wp-admin/</loc></url><url><loc>https://www.firm.example/wp-login.php</loc></url><url><loc>https://www.firm.example/xmlrpc.php</loc></url><url><loc>https://www.firm.example/wp-json/wp/v2/users</loc></url><url><loc>https://elsewhere.example/</loc></url></urlset>';
		$parsed = Discovery::parse_sitemap( $xml );
		$cands  = array();
		foreach ( $parsed['urls'] as $u ) {
			$cands[] = array( 'url' => $u, 'source' => 'sitemap', 'post_id' => 0, 'exclude' => '' );
		}
		$cands[] = array( 'url' => 'https://www.firm.example/?p=12', 'source' => 'post:post', 'post_id' => 12, 'exclude' => '' );
		$cands[] = array( 'url' => 'https://www.firm.example/private-page/', 'source' => 'post:page', 'post_id' => 13, 'exclude' => 'password_protected' );
		$frozen  = Discovery::freeze( $cands, $policy, 2000 );
		$pending = array();
		$reasons = array();
		foreach ( $frozen['urls'] as $u ) {
			if ( 'pending' === $u['coverage'] ) {
				$pending[] = $u['url'];
			} else {
				$reasons[ $u['url'] ] = $u['reason'];
			}
		}
		check_same( array( 'https://www.firm.example/about/', 'https://www.firm.example/?p=12' ), $pending, 'Only safe URLs are fetched; WordPress permalinks keep their query' );
		foreach ( $reasons as $url => $reason ) {
			check( '' !== $reason, 'Exclusion has a reason: ' . $url );
		}
		check_same( 'password_protected', $reasons['https://www.firm.example/private-page/'], 'Password-protected recorded' );
		check_same( 'off_site_host', $reasons['https://elsewhere.example/'], 'Off-site recorded' );
	}
);

mltsa_test(
	'AC scope: the URL cap records the rest as excluded, and a sitemap index lists child sitemaps',
	static function () {
		$policy = new UrlPolicy( 'https://www.firm.example/', false, static function () {
			return array( '203.0.113.10' );
		} );
		$cands = array();
		for ( $i = 0; $i < 5; $i++ ) {
			$cands[] = array( 'url' => 'https://www.firm.example/p' . $i . '/', 'source' => 'sitemap', 'post_id' => 0, 'exclude' => '' );
		}
		$frozen = Discovery::freeze( $cands, $policy, 3 );
		check_same( 3, $frozen['included'], 'Three included' );
		check_same( array( 'url_cap' => 2 ), $frozen['excluded_by_reason'], 'Two over the cap' );
		$index = Discovery::parse_sitemap( '<sitemapindex><sitemap><loc>https://www.firm.example/page-sitemap.xml</loc></sitemap></sitemapindex>' );
		check_same( array( 'https://www.firm.example/page-sitemap.xml' ), $index['sitemaps'], 'Index entries are sitemaps' );
	}
);
