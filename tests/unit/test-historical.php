<?php
/**
 * The historical fixture set: every known defect from the July to August
 * 2026 pilot evidence must be detected, and every must-not-flag case must
 * pass. Fixtures are anonymised (fictional firms, reserved .example hosts,
 * Ofcom drama-range numbers); IDs match the local defect catalogue.
 *
 * Each fixture runs through the same engine path as the worker: extract,
 * evaluate each page, then the site rules over all pages, then the resource
 * check with stubbed HTTP statuses.
 *
 * @package MLT\SchemaAudit
 */

// phpcs:disable

use MLT\SchemaAudit\Engine\Evaluator;
use MLT\SchemaAudit\Engine\Extractor;
use MLT\SchemaAudit\Engine\Rules;
use MLT\SchemaAudit\Engine\SiteRules;

/**
 * Build a page's HTML from a fixture page.
 *
 * @param array $page Fixture page.
 * @return string
 */
function fixture_html( array $page ) {
	if ( isset( $page['html'] ) ) {
		return $page['html'];
	}
	$scripts = '';
	foreach ( isset( $page['blocks'] ) ? $page['blocks'] : array() as $block ) {
		$scripts .= '<script type="application/ld+json">' . json_encode( $block, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE ) . '</script>';
	}
	foreach ( isset( $page['raw_blocks'] ) ? $page['raw_blocks'] : array() as $raw ) {
		$scripts .= '<script type="application/ld+json">' . $raw . '</script>';
	}
	$head = '<meta charset="utf-8">' . ( isset( $page['head'] ) ? $page['head'] : '' );
	return '<!doctype html><html><head>' . $head . $scripts . '</head><body>' . ( isset( $page['body'] ) ? $page['body'] : '' ) . '</body></html>';
}

/**
 * Run a fixture through the engine.
 *
 * @param array $fx Fixture.
 * @return array { findings, parsed, blocks }
 */
function run_fixture( array $fx ) {
	$parts  = parse_url( $fx['site'] );
	$host   = strtolower( $parts['host'] );
	$other  = 0 === strpos( $host, 'www.' ) ? substr( $host, 4 ) : 'www.' . $host;
	$base   = $parts['scheme'] . '://' . $host;
	$all    = array();
	$facts  = array();
	$parsed = 0;
	$blocks = array();
	foreach ( $fx['pages'] as $i => $page ) {
		$url_id     = $i + 1;
		$extraction = ( new Extractor() )->extract( fixture_html( $page ) );
		if ( 0 === $i ) {
			$blocks = $extraction['blocks'];
		}
		$evaluator = new Evaluator(
			array_merge(
				array(
					'page_url'    => $base . $page['path'],
					'own_hosts'   => array( $host, $other ),
					'home_scheme' => $parts['scheme'],
				),
				isset( $fx['context'] ) ? $fx['context'] : array()
			)
		);
		$result            = $evaluator->evaluate( $extraction );
		$parsed           += $result['parsed'];
		$facts[ $url_id ]  = $result['site'];
		foreach ( $result['findings'] as $finding ) {
			$all[] = $finding + array( 'page' => $page['path'] );
		}
	}
	foreach ( SiteRules::evaluate( $facts ) as $url_id => $findings ) {
		foreach ( $findings as $finding ) {
			$all[] = $finding + array( 'page' => $fx['pages'][ $url_id - 1 ]['path'] );
		}
	}
	$statuses = isset( $fx['resources'] ) ? $fx['resources'] : array();
	foreach ( SiteRules::resources( $facts ) as $url => $where_list ) {
		$status = isset( $statuses[ $url ] ) ? (int) $statuses[ $url ] : 0;
		if ( 404 !== $status && 410 !== $status ) {
			continue;
		}
		foreach ( $where_list as $where ) {
			$all[] = SiteRules::broken_resource( $url, $where, $status ) + array( 'page' => $fx['pages'][ $where['url_id'] - 1 ]['path'] );
		}
	}
	return array(
		'findings' => $all,
		'parsed'   => $parsed,
		'blocks'   => $blocks,
	);
}

/**
 * Short description of findings for failure messages.
 *
 * @param array $findings Findings.
 * @return string
 */
function describe_findings( array $findings ) {
	$out = array();
	foreach ( $findings as $f ) {
		$out[] = $f['rule_id'] . '/' . $f['outcome'] . '/' . $f['severity'] . ( '' !== $f['property'] ? ':' . $f['property'] : '' );
	}
	return empty( $out ) ? '(none)' : implode( ', ', $out );
}

foreach ( array_merge( glob( dirname( __DIR__ ) . '/fixtures/historical/*.json' ), glob( dirname( __DIR__ ) . '/fixtures/regression/*.json' ) ) as $file ) {
	$fx = json_decode( file_get_contents( $file ), true );
	mltsa_test(
		'HIST ' . $fx['id'] . ' ' . $fx['summary'],
		static function () use ( $fx ) {
			$run      = run_fixture( $fx );
			$findings = $run['findings'];
			$by_rule  = array();
			foreach ( $findings as $f ) {
				$by_rule[ $f['rule_id'] ][] = $f;
			}
			$seen   = describe_findings( $findings );
			$expect = $fx['expect'];

			foreach ( isset( $expect['fires'] ) ? $expect['fires'] : array() as $rule ) {
				check( isset( $by_rule[ $rule ] ), "{$rule} should fire; got {$seen}" );
			}
			if ( ! empty( $expect['fires_any'] ) ) {
				check( count( array_intersect( $expect['fires_any'], array_keys( $by_rule ) ) ) > 0, 'One of ' . implode( ', ', $expect['fires_any'] ) . " should fire; got {$seen}" );
			}
			foreach ( isset( $expect['absent'] ) ? $expect['absent'] : array() as $rule ) {
				check( ! isset( $by_rule[ $rule ] ), "{$rule} must not fire; got {$seen}" );
			}
			if ( ! empty( $expect['no_fail'] ) ) {
				foreach ( $findings as $f ) {
					check( 'fail' !== $f['outcome'], "No finding may be a fail; got {$seen}" );
				}
			}
			foreach ( isset( $expect['min_count'] ) ? $expect['min_count'] : array() as $rule => $n ) {
				check( isset( $by_rule[ $rule ] ) && count( $by_rule[ $rule ] ) >= $n, "{$rule} should fire at least {$n} times; got {$seen}" );
			}
			foreach ( isset( $expect['max_count'] ) ? $expect['max_count'] : array() as $rule => $n ) {
				check( ! isset( $by_rule[ $rule ] ) || count( $by_rule[ $rule ] ) <= $n, "{$rule} should fire at most {$n} times; got {$seen}" );
			}
			foreach ( isset( $expect['outcome'] ) ? $expect['outcome'] : array() as $rule => $outcome ) {
				$outcomes = isset( $by_rule[ $rule ] ) ? array_column( $by_rule[ $rule ], 'outcome' ) : array();
				check( in_array( $outcome, $outcomes, true ), "{$rule} should have outcome {$outcome}; got {$seen}" );
			}
			foreach ( isset( $expect['absent_property'] ) ? $expect['absent_property'] : array() as $rule => $props ) {
				foreach ( isset( $by_rule[ $rule ] ) ? $by_rule[ $rule ] : array() as $f ) {
					check( ! in_array( $f['property'], $props, true ), "{$rule} must not report {$f['property']}; got {$seen}" );
				}
			}
			if ( isset( $expect['parsed'] ) ) {
				check_same( $expect['parsed'], $run['parsed'], 'Parsed blocks' );
			}
			foreach ( isset( $expect['block_source'] ) ? $expect['block_source'] : array() as $index => $source ) {
				check_same( $source, $run['blocks'][ (int) $index ]['source'], "Source of block {$index}" );
			}
			if ( ! empty( $expect['clean'] ) ) {
				$allow = isset( $expect['allow'] ) ? $expect['allow'] : array();
				foreach ( $findings as $f ) {
					check( 'info' === $f['severity'] || in_array( $f['rule_id'], $allow, true ), "Must-not-flag case raised {$f['rule_id']}; got {$seen}" );
				}
			}
		}
	);
}

mltsa_test(
	'HIST every catalogue ID has exactly one fixture',
	static function () {
		$ids = array();
		foreach ( glob( dirname( __DIR__ ) . '/fixtures/historical/*.json' ) as $file ) {
			$fx    = json_decode( file_get_contents( $file ), true );
			$ids[] = $fx['id'];
			check_same( basename( $file, '.json' ), $fx['id'], 'File name matches ID' );
		}
		$expected = array();
		for ( $i = 1; $i <= 50; $i++ ) {
			$expected[] = sprintf( 'D%02d', $i );
		}
		for ( $i = 1; $i <= 21; $i++ ) {
			$expected[] = sprintf( 'FP%02d', $i );
		}
		sort( $ids );
		sort( $expected );
		check_same( $expected, $ids, 'Fixture IDs' );
	}
);

mltsa_test(
	'Review reply: a broken own-host sameAs link is not reported as a broken image; a broken own-host logo still is',
	static function () {
		$site = 'https://www.firm-sameas.example';
		$fx   = array(
			'site'      => $site,
			'pages'     => array(
				array(
					'path'   => '/',
					'body'   => '<p>Firm</p>',
					'blocks' => array(
						array(
							'@context' => 'https://schema.org',
							'@type'    => 'LegalService',
							'@id'      => $site . '/#org',
							'name'     => 'Firm',
							'logo'     => $site . '/wp-content/uploads/logo.png',
							'sameAs'   => array( $site . '/about-us/', 'https://firm-sameas.example/team/' ),
						),
					),
				),
			),
			'resources' => array(
				$site . '/wp-content/uploads/logo.png' => 404,
				$site . '/about-us/'                   => 404,
				'https://firm-sameas.example/team/'    => 410,
			),
		);
		$broken = array();
		foreach ( run_fixture( $fx )['findings'] as $f ) {
			if ( 'URL-004' === $f['rule_id'] ) {
				$broken[] = $f['property'] . ' ' . $f['observed'];
			}
		}
		check_same( array( 'logo ' . $site . '/wp-content/uploads/logo.png' ), $broken, 'Only the logo is a broken file' );
		check_same( 3, Rules::get( 'URL-004' )['version'], 'URL-004 version bumped, so open sameAs issues are held as a rule change, not cleared as fixed' );
	}
);

mltsa_test(
	'Owner decision 2026-11-02: URL-008 reports a broken own-host sameAs profile link as a page; other hosts are never checked',
	static function () {
		$site = 'https://www.firm-links.example';
		$fx   = array(
			'site'      => $site,
			'pages'     => array(
				array(
					'path'   => '/',
					'body'   => '<p>Firm</p>',
					'blocks' => array(
						array(
							'@context' => 'https://schema.org',
							'@type'    => 'LegalService',
							'@id'      => $site . '/#org',
							'name'     => 'Firm',
							'logo'     => $site . '/wp-content/uploads/logo.png',
							'sameAs'   => array( 'https://social.example/firm', $site . '/about-us/' ),
							'founder'  => array(
								'@type'  => 'Person',
								'name'   => 'Person A',
								'sameAs' => array( 'https://firm-links.example/team/person-a/', $site . '/team/person-b/' ),
							),
						),
					),
				),
			),
			'resources' => array(
				$site . '/wp-content/uploads/logo.png'      => 404,
				$site . '/about-us/'                        => 200,
				'https://firm-links.example/team/person-a/' => 410,
				$site . '/team/person-b/'                   => 404,
				'https://social.example/firm'               => 404,
			),
		);
		$by_rule = array();
		foreach ( run_fixture( $fx )['findings'] as $f ) {
			if ( in_array( $f['rule_id'], array( 'URL-004', 'URL-008' ), true ) ) {
				$by_rule[ $f['rule_id'] ][] = $f['property'] . ' ' . $f['observed'] . ' ' . $f['comparison'];
			}
		}
		check_same( array( 'logo ' . $site . '/wp-content/uploads/logo.png HTTP 404' ), isset( $by_rule['URL-004'] ) ? $by_rule['URL-004'] : array(), 'URL-004: the logo only' );
		$links = isset( $by_rule['URL-008'] ) ? $by_rule['URL-008'] : array();
		sort( $links );
		check_same( array( 'sameAs https://firm-links.example/team/person-a/ HTTP 410', 'sameAs ' . $site . '/team/person-b/ HTTP 404' ), $links, 'URL-008: both broken own-host profile links (www and bare), not the live one' );

		$facts = array();
		foreach ( $fx['pages'] as $i => $page ) {
			$extraction      = ( new Extractor() )->extract( fixture_html( $page ) );
			$facts[ $i + 1 ] = ( new Evaluator(
				array(
					'page_url'    => $site . '/',
					'own_hosts'   => array( 'www.firm-links.example', 'firm-links.example' ),
					'home_scheme' => 'https',
				)
			) )->evaluate( $extraction )['site'];
		}
		$listed = SiteRules::resources( $facts );
		check( ! isset( $listed['https://social.example/firm'] ), 'The other host is never queued for a request' );
		check_same( 4, count( $listed ), 'Logo and three own-host links share the one resource budget' );
		check( SiteRules::is_file_check( $listed[ $site . '/wp-content/uploads/logo.png' ] ), 'The logo is requested as a file' );
		check( ! SiteRules::is_file_check( $listed[ $site . '/team/person-b/' ] ), 'A profile link is requested as a page (normal page policy)' );
		check_same( array( 'unchecked' ), array_values( array_unique( SiteRules::resource_outcomes( $facts, array() ) ) ), 'An unchecked profile link holds its issue like an unchecked image' );

		$url004 = Rules::get( 'URL-004' );
		$url008 = Rules::get( 'URL-008' );
		$rank   = array(
			'info'   => 0,
			'low'    => 1,
			'medium' => 2,
			'high'   => 3,
		);
		check( $rank[ $url008['severity'] ] <= $rank[ $url004['severity'] ], 'URL-008 severity is no higher than URL-004' );
		check_same( '2026.11.2', Rules::RULESET_VERSION, 'Rule set version bumped for the new rule' );
	}
);

mltsa_test(
	'HIST fixtures hold no client names, real hosts or non-fictional phone numbers',
	static function () {
		require_once dirname( __DIR__ ) . '/support/client-names.php';
		foreach ( glob( dirname( __DIR__ ) . '/fixtures/historical/*.json' ) as $file ) {
			$text = file_get_contents( $file );
			$hit = mltsa_client_name_hit( $text );
			check( '' === $hit, basename( $file ) . ' contains a client name: ' . $hit );
			preg_match_all( '/(?:\+44[\s\-]?|\b0)(\d[\d\s\-]{8,12}\d)/', $text, $numbers );
			foreach ( $numbers[0] as $number ) {
				$digits = preg_replace( '/\D/', '', $number );
				$digits = preg_replace( '/^44/', '0', $digits );
				check( 0 === strpos( $digits, '01632960' ) || 0 === strpos( $digits, '0808157' ), basename( $file ) . " has a number outside the Ofcom drama ranges {$number}" );
			}
		}
	}
);
