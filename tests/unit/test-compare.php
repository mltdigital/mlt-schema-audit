<?php
/**
 * Unit tests for the issue register: site-wide issues are cleared only when
 * the evidence they rest on was read again (review finding 2, 2026-10-30).
 *
 * @package MLT\SchemaAudit
 */

// phpcs:disable

use MLT\SchemaAudit\Engine\Comparator;
use MLT\SchemaAudit\Engine\SiteRules;

/**
 * A stored site-wide issue.
 *
 * @param array  $refs     Evidence refs ('' leaves the column empty, as before 0.1.1).
 * @param string $rule_id  Rule.
 * @param string $entity   Entity key.
 * @return array
 */
function site_issue( $refs, $rule_id = 'SITE-001', $entity = 'https://firm.example/#org' ) {
	return array(
		'id'                 => 1,
		'page_url'           => '',
		'site_wide'          => '1',
		'rule_id'            => $rule_id,
		'rule_version'       => 1,
		'entity_key'         => $entity,
		'verification_state' => 'present',
		'work_status'        => 'open',
		'observed_hash'      => 'h',
		'evidence'           => '' === $refs ? '' : json_encode( $refs ),
	);
}

/**
 * Reconcile one stored issue against a run with no findings.
 *
 * @param array $issue     Issue.
 * @param array $pages     url_key => coverage.
 * @param array $resources Resource URL => outcome.
 * @param bool  $full      Full scope.
 * @return string|null New verification state, or null when untouched.
 */
function reconcile_one( array $issue, array $pages, array $resources = array(), $full = true ) {
	$fp  = array( $issue['rule_id'] => 1 );
	$out = Comparator::reconcile( array( 'k' => $issue ), array(), $pages, $fp, $fp, $full, $resources );
	return isset( $out['update']['k']['verification_state'] ) ? $out['update']['k']['verification_state'] : null;
}

mltsa_test(
	'Review 2: a SITE-001 issue whose only page timed out is unavailable, not no longer detected',
	static function () {
		$issue = site_issue( array( 'firm.example/contact' ) );
		check_same( 'unavailable', reconcile_one( $issue, array( 'firm.example/contact' => 'timeout' ) ), 'Timeout holds the issue' );
		check_same( 'unavailable', reconcile_one( $issue, array( 'firm.example/contact' => 'pending' ) ), 'Unread page (failed run) holds the issue' );
		check_same( 'no_longer_detected', reconcile_one( $issue, array( 'firm.example/contact' => 'ok' ) ), 'Read page clears it' );
	}
);

mltsa_test(
	'Review 2: a page with the common value that was not read holds the issue, even when the differing page was read',
	static function () {
		$issue = site_issue( array( 'firm.example', 'firm.example/about', 'firm.example/contact' ) );
		$pages = array(
			'firm.example'         => 'error',
			'firm.example/about'   => 'ok',
			'firm.example/contact' => 'ok',
		);
		check_same( 'unavailable', reconcile_one( $issue, $pages ), 'One unread supporting page' );
		$pages['firm.example'] = 'not_found';
		check_same( 'no_longer_detected', reconcile_one( $issue, $pages ), 'A removed page is conclusive' );
	}
);

mltsa_test(
	'Review 2: a narrowed scope (supporting page excluded or not discovered) leaves the issue untouched',
	static function () {
		$issue = site_issue( array( 'firm.example/about', 'firm.example/team/jane' ) );
		check_same( null, reconcile_one( $issue, array( 'firm.example/about' => 'ok' ) ), 'Page outside this run' );
		check_same( null, reconcile_one( $issue, array( 'firm.example/about' => 'ok', 'firm.example/team/jane' => 'ok' ), array(), false ), 'Recheck of listed URLs never touches site-wide issues' );
		check_same( 'unavailable', reconcile_one( $issue, array( 'firm.example/about' => 'timeout' ) ), 'Unknown outranks missing' );
	}
);

mltsa_test(
	'Review 2: URL-004 is cleared only when its resource was checked, or no page read references it any more',
	static function () {
		$img   = 'https://firm.example/wp-content/uploads/logo.png';
		$issue = site_issue( array( 'firm.example', 'resource:' . $img ), 'URL-004', 'resource:' . $img );
		$pages = array( 'firm.example' => 'ok' );
		check_same( 'unavailable', reconcile_one( $issue, $pages, array( $img => 'unchecked' ) ), 'Over the cap or check unfinished' );
		check_same( 'unavailable', reconcile_one( $issue, $pages, array( $img => 'blocked' ) ), 'Check blocked by policy' );
		check_same( 'unavailable', reconcile_one( $issue, $pages, array( $img => 'timeout' ) ), 'Check timed out' );
		check_same( 'no_longer_detected', reconcile_one( $issue, $pages, array( $img => 'ok' ) ), 'Checked and fine' );
		check_same( 'no_longer_detected', reconcile_one( $issue, $pages, array() ), 'Page read and no longer references it' );
		check_same( 'unavailable', reconcile_one( $issue, array( 'firm.example' => 'timeout' ), array() ), 'Referencing page not read' );
	}
);

mltsa_test(
	'Review 2: an issue stored without evidence clears only when every page in the run was read',
	static function () {
		$issue = site_issue( '' );
		check_same( 'unavailable', reconcile_one( $issue, array( 'firm.example' => 'ok', 'firm.example/a' => 'timeout' ) ), 'Any unread page' );
		check_same( 'no_longer_detected', reconcile_one( $issue, array( 'firm.example' => 'ok', 'firm.example/a' => 'gone' ) ), 'Full coverage' );
		check_same( null, reconcile_one( $issue, array() ), 'No pages at all is not evidence' );
		check_same( 'missing', Comparator::evidence_state( array( 'resource:https://firm.example/x.png' ), array(), array() ), 'A resource ref alone is not evidence' );
	}
);

mltsa_test(
	'Review 2: the digest counts a site-wide issue as resolved only when its evidence was read',
	static function () {
		$base = array(
			'findings'    => array(
				'k' => array( 'hash' => 'h', 'rule_id' => 'SITE-001', 'page' => '', 'refs' => array( 'firm.example', 'firm.example/contact' ) ),
			),
			'pages'       => array(
				'firm.example'         => array( 'coverage' => 'ok', 'markup' => 'a' ),
				'firm.example/contact' => array( 'coverage' => 'ok', 'markup' => 'b' ),
			),
			'fingerprint' => array( 'SITE-001' => 1 ),
		);
		$now = array(
			'findings'    => array(),
			'pages'       => array(
				'firm.example'         => array( 'coverage' => 'ok', 'markup' => 'a' ),
				'firm.example/contact' => array( 'coverage' => 'timeout', 'markup' => '' ),
			),
			'fingerprint' => array( 'SITE-001' => 1 ),
		);
		check_same( array(), Comparator::compare( $base, $now )['resolved'], 'Timed-out evidence is not a fix' );
		$now['pages']['firm.example/contact']['coverage'] = 'ok';
		check_same( array( 'k' ), Comparator::compare( $base, $now )['resolved'], 'Read evidence is' );
		unset( $base['findings']['k']['refs'] );
		check_same( array(), Comparator::compare( $base, $now )['resolved'], 'No refs, no resolved count' );
	}
);

mltsa_test(
	'Review 2: SITE-001 evidence covers every page carrying the entity; URL-004 evidence names the resource and its pages',
	static function () {
		$entity = static function ( $phone ) {
			return array(
				'type'      => 'LegalService',
				'name'      => 'Firm',
				'phones'    => array( $phone ),
				'postcodes' => array(),
				'logo'      => array(),
				'rating'    => array(),
				'links'     => array(),
				'path'      => "['@graph'][0]",
				'block'     => 0,
			);
		};
		$id    = 'https://firm.example/#org';
		$img   = 'https://firm.example/wp-content/uploads/logo.png';
		$facts = array(
			1 => array( 'entities' => array( $id => array( $entity( '1414960678' ) ) ), 'resources' => array( $img => array( 'prop' => 'logo', 'path' => "['@graph'][0]['logo']", 'block' => 0 ) ) ),
			2 => array( 'entities' => array( $id => array( $entity( '1414960678' ) ) ) ),
			3 => array( 'entities' => array( $id => array( $entity( '1414960999' ) ) ) ),
			4 => array(),
		);
		$urls     = array(
			1 => 'https://firm.example/',
			2 => 'https://firm.example/about/',
			3 => 'https://firm.example/contact/',
			4 => 'https://firm.example/blog/',
		);
		$evidence = SiteRules::evidence( $facts, $urls );
		$site     = array();
		foreach ( SiteRules::evaluate( $facts ) as $findings ) {
			foreach ( $findings as $f ) {
				$site[ Comparator::issue_key( '', $f ) ] = $f['rule_id'];
			}
		}
		$key = array_search( 'SITE-001', $site, true );
		check( false !== $key, 'SITE-001 fires on the differing phone' );
		check_same( array( 'firm.example', 'firm.example/about', 'firm.example/contact' ), $evidence[ $key ], 'Common-value pages are evidence too; the page without the entity is not' );

		$url_key = Comparator::issue_key( '', SiteRules::broken_resource( $img, $facts[1]['resources'][ $img ], 404 ) );
		check_same( array( 'firm.example', 'resource:' . $img ), $evidence[ $url_key ], 'URL-004 evidence' );
		check_same( array( $img => 'unchecked' ), SiteRules::resource_outcomes( $facts, array() ), 'Referenced but not checked' );
		check_same( array( $img => 'ok' ), SiteRules::resource_outcomes( $facts, array( $img => 'ok', 'https://firm.example/old.png' => 'ok' ) ), 'Only resources a page read references' );
		check_same(
			array(
				'referenced' => 5,
				'attempted'  => 4,
				'checked'    => 3,
				'broken'     => 2,
			),
			SiteRules::resource_counts(
				array(
					'https://firm.example/a.png' => 'ok',
					'https://firm.example/b.png' => 'not_found',
					'https://firm.example/c.png' => 'gone',
					'https://firm.example/d.png' => 'blocked',
					'https://firm.example/e.png' => 'unchecked',
				)
			),
			'Checked counts only answers; blocked is attempted, not checked'
		);
	}
);

mltsa_test(
	'Review 7: a removed or re-versioned rule is held, not reported as a website fix',
	static function () {
		$pages = array( 'firm.example/a' => array( 'coverage' => 'ok', 'markup' => 'm' ) );
		$base  = array(
			'findings'    => array(
				'p' => array( 'hash' => 'h', 'rule_id' => 'ID-001', 'page' => 'firm.example/a' ),
				'q' => array( 'hash' => 'h', 'rule_id' => 'ID-002', 'page' => 'firm.example/a' ),
			),
			'pages'       => $pages,
			'fingerprint' => array( 'ID-001' => 1, 'ID-002' => 1 ),
		);
		// ID-001 removed from the rule set; ID-002 unchanged and no longer firing.
		$now    = array(
			'findings'    => array(),
			'pages'       => $pages,
			'fingerprint' => array( 'ID-002' => 1 ),
		);
		$result = Comparator::compare( $base, $now );
		check_same( array( 'ID-001' ), $result['rules_changed'], 'The removed rule is a rule change' );
		check_same( array( 'q' ), $result['resolved'], 'Only the rule that still exists can be a website fix' );
		check_same( array( 'p' ), $result['held_rule_change'], 'The removed rule is held' );

		// Re-versioned rule: finding gone is held; finding with different evidence is a rule-driven change.
		$base['findings']['q']['hash'] = 'old';
		$now['fingerprint']            = array( 'ID-002' => 2 );
		$now['findings']               = array( 'q' => array( 'hash' => 'new', 'rule_id' => 'ID-002', 'page' => 'firm.example/a' ) );
		$result                        = Comparator::compare( $base, $now );
		check_same( array( 'q' ), $result['changed_rule_change'], 'Evidence change under a changed rule is a rule change' );
		check_same( array(), $result['changed'], 'Not a website change' );
		check_same( array( 'p' ), $result['held_rule_change'], 'ID-001 is now absent from the rule set' );
		check_same( array(), $result['resolved'], 'Nothing resolved' );
	}
);

mltsa_test(
	'Review reply: repeated "unavailable" is counted per issue across audits in a row, without changing any issue state',
	static function () {
		$page  = array(
			'id'                 => 7,
			'page_url'           => 'https://firm.example/about/',
			'site_wide'          => '0',
			'rule_id'            => 'FACT-001',
			'rule_version'       => 1,
			'entity_key'         => '',
			'verification_state' => 'unavailable',
			'work_status'        => 'in_progress',
			'observed_hash'      => 'h',
			'evidence'           => '',
		);
		$site  = site_issue( array( 'firm.example/about' ) );
		$fp    = array( 'FACT-001' => 1, 'SITE-001' => 1 );
		$out   = Comparator::reconcile( array( 'p' => $page, 's' => $site ), array(), array( 'firm.example/about' => 'timeout' ), $fp, $fp, true );
		check_same( array( 'p', 's' ), $out['unavailable'], 'Both issues listed as unavailable in this run' );
		check( ! isset( $out['update']['p'] ), 'An issue already unavailable gets no update' );
		check_same( array( 'verification_state' => 'unavailable' ), $out['update']['s'], 'The other only moves to unavailable, as before' );

		// Audits in a row: 1, then 2, carried over while out of scope, reset once read.
		$first = Comparator::unavailable_streaks( array(), array( 7, 1 ), array() );
		check_same( array( 1 => 1, 7 => 1 ), $first, 'First audit' );
		$second = Comparator::unavailable_streaks( $first, array( 7 ), array( 1 ) );
		check_same( array( 1 => 1, 7 => 2 ), $second, 'Issue 7 twice in a row; issue 1 outside the run keeps its count' );
		$third = Comparator::unavailable_streaks( $second, array( 7, 9 ), array() );
		check_same( array( 7 => 3, 9 => 1 ), $third, 'Issue 1 read again (no longer unavailable) is dropped; 9 starts at 1' );

		$fig = Comparator::repeat_unavailable( $third, array( 7, 9 ) );
		check_same( array( 'min_runs' => 2, 'issues' => 1, 'longest' => 3, 'ids' => array( 7 ) ), $fig, 'Figure counts only issues unavailable in this run for 2 or more audits' );
		$none = Comparator::repeat_unavailable( $second, array() );
		check_same( 0, $none['issues'], 'An issue only carried over is not counted for this run' );
		$many = array();
		for ( $i = 1; $i <= 60; $i++ ) {
			$many[ $i ] = 2 + ( $i % 5 );
		}
		$big = Comparator::repeat_unavailable( $many, array_keys( $many ) );
		check_same( 60, $big['issues'], 'All counted' );
		check_same( 50, count( $big['ids'] ), 'At most 50 IDs listed' );
		check_same( 6, $many[ $big['ids'][0] ], 'Longest first' );
	}
);

mltsa_test(
	'PHP 7.4: the most common site-wide value is chosen the same way on PHP 7.4 (unstable sort) as on PHP 8; ties keep first-seen order',
	static function () {
		$map      = array();
		$expected = array();
		for ( $i = 0; $i < 40; $i++ ) {
			$map[ 'v' . $i ] = 0 === $i % 7 ? array( 1, 2 ) : array( 1 );
		}
		foreach ( $map as $key => $list ) {
			if ( 2 === count( $list ) ) {
				$expected[] = $key;
			}
		}
		foreach ( $map as $key => $list ) {
			if ( 1 === count( $list ) ) {
				$expected[] = $key;
			}
		}
		check_same( $expected, array_keys( SiteRules::by_count_desc( $map ) ), 'Largest first, ties in original order' );
		check_same( array( '0141', '0161' ), array_keys( SiteRules::by_count_desc( array( '0141' => array( 'a' ), '0161' => array( 'b' ) ) ) ), 'Numeric-looking keys keep their order on a tie' );
	}
);

mltsa_test(
	'Branch review R2: a site-wide issue whose evidence page left the site, or is not HTML, is no longer held for ever',
	static function () {
		$issue = site_issue( array( 'firm.example/about', 'firm.example/old-duplicate' ) );
		$pages = array( 'firm.example' => 'ok', 'firm.example/about' => 'ok' );
		check_same( null, reconcile_one( $issue, $pages ), 'Not listed and not known to be gone: held, as finding 2 requires' );
		$fp  = array( 'SITE-001' => 1 );
		$out = Comparator::reconcile( array( 'k' => $issue ), array(), $pages, $fp, $fp, true, array(), array( 'firm.example/old-duplicate' => true ) );
		check_same( 'no_longer_detected', $out['update']['k']['verification_state'], 'Unpublished or deleted page settles its part' );
		$out = Comparator::reconcile( array( 'k' => $issue ), array(), array( 'firm.example/about' => 'timeout' ), $fp, $fp, true, array(), array( 'firm.example/old-duplicate' => true ) );
		check_same( 'unavailable', $out['update']['k']['verification_state'], 'The other page unread still holds it as unavailable' );
		$pages['firm.example/old-duplicate'] = 'not_html';
		check_same( 'no_longer_detected', reconcile_one( $issue, $pages ), 'A page read as not HTML carries no JSON-LD: settled' );
		check_same( 'read', Comparator::evidence_state( array( 'firm.example/gone' ), array(), array(), array( 'firm.example/gone' => true ) ), 'Only gone pages: read' );
		check_same( 'missing', Comparator::evidence_state( array( 'firm.example/gone' ), array(), array(), array( 'firm.example/other' => true ) ), 'Gone list is per page' );

		$base = array(
			'findings'    => array( 'k' => array( 'hash' => 'h', 'rule_id' => 'SITE-001', 'page' => '', 'refs' => array( 'firm.example/about', 'firm.example/old-duplicate' ) ) ),
			'pages'       => array(),
			'fingerprint' => $fp,
		);
		$now  = array(
			'findings'    => array(),
			'pages'       => array( 'firm.example/about' => array( 'coverage' => 'ok', 'markup' => 'a' ) ),
			'fingerprint' => $fp,
		);
		check_same( array(), Comparator::compare( $base, $now )['resolved'], 'Digest: held while the page may still exist' );
		$now['gone'] = array( 'firm.example/old-duplicate' => true );
		check_same( array( 'k' ), Comparator::compare( $base, $now )['resolved'], 'Digest: resolved once the page has left the site' );
	}
);
