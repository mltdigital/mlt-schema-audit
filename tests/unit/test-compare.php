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
			1 => array( 'entities' => array( $id => array( $entity( '1412345678' ) ) ), 'resources' => array( $img => array( 'prop' => 'logo', 'path' => "['@graph'][0]['logo']", 'block' => 0 ) ) ),
			2 => array( 'entities' => array( $id => array( $entity( '1412345678' ) ) ) ),
			3 => array( 'entities' => array( $id => array( $entity( '1419999999' ) ) ) ),
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
