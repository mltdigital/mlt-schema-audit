<?php
/**
 * Extraction acceptance cases and threat model F4, F5.
 *
 * @package MLT\SchemaAudit
 */

// phpcs:disable

use MLT\SchemaAudit\Engine\Extractor;
use MLT\SchemaAudit\Engine\Graph;

mltsa_test(
	'AC extraction: quoted, single-quoted, unquoted and odd-case type attributes all found',
	static function () {
		$html = '<html><head>'
			. '<script type="application/ld+json">{"@context":"https://schema.org","@type":"WebSite","name":"A"}</script>'
			. "<script type='application/ld+json'>{\"@context\":\"https://schema.org\",\"@type\":\"WebPage\",\"name\":\"B\"}</script>"
			. '<script type=application/ld+json>{"@context":"https://schema.org","@type":"Organization","name":"C"}</script>'
			. '<SCRIPT TYPE=" Application/LD+JSON ; charset=utf-8" class=x>{"@context":"https://schema.org","@type":"Person","name":"D"}</SCRIPT >'
			. '<script type="text/javascript">var x = {"@type":"Organization"};</script>'
			. '<script type="application/ld+json"><!--{"@context":"https://schema.org","@type":"Service","name":"E"}--></script>'
			. '</head><body></body></html>';
		$out  = ( new Extractor() )->extract( $html );
		check_same( 5, count( $out['blocks'] ), 'five JSON-LD blocks, the JavaScript block ignored' );
		foreach ( $out['blocks'] as $block ) {
			check_same( 'ok', $block['parse'], 'block ' . $block['index'] . ' parsed' );
		}
		check_same( 'Service', $out['blocks'][4]['data']['@type'], 'comment wrapper removed' );
	}
);

mltsa_test(
	'AC extraction: malformed JSON keeps the parser\'s original error and raw text',
	static function () {
		$out = ( new Extractor() )->extract( '<script type="application/ld+json">{"@context":"https://schema.org","@type":"LegalService","name":"X",}</script>' );
		check_same( 'error', $out['blocks'][0]['parse'], 'parse failure' );
		check( '' !== $out['blocks'][0]['error'], 'original error kept' );
		check( false !== strpos( $out['blocks'][0]['raw'], '"name":"X",}' ), 'raw text kept as evidence' );
		$result = audit_html( '<script type="application/ld+json">{"@type":"LegalService",}</script>' );
		check( in_array( 'SYN-001', rule_ids( $result['findings'] ), true ), 'SYN-001 reported' );
	}
);

mltsa_test(
	'AC extraction: entity-encoded JSON-LD is a parse failure with the decoded form kept as evidence',
	static function () {
		$html = '<script type="application/ld+json">{&quot;@context&quot;:&quot;https://schema.org&quot;,&quot;@type&quot;:&quot;LegalService&quot;,&quot;name&quot;:&quot;Example Legal&quot;}</script>';
		$out  = ( new Extractor() )->extract( $html );
		check_same( 'error', $out['blocks'][0]['parse'], 'reported as not parsing' );
		check( $out['blocks'][0]['entity_encoded'], 'entity encoding recognised' );
		check_same( 'LegalService', $out['blocks'][0]['data']['@type'], 'decoded form kept' );
		$ids = rule_ids( audit_html( $html )['findings'] );
		check( in_array( 'SYN-002', $ids, true ) && ! in_array( 'SYN-001', $ids, true ), 'SYN-002, not SYN-001' );
	}
);

mltsa_test(
	'AC extraction: multiple blocks, @graph and arrays are all indexed; types kept, including helper types',
	static function () {
		$html = '<script type="application/ld+json">{"@context":"https://schema.org","@graph":[{"@type":"WebSite","@id":"https://www.example-legal.co.uk/#website"},{"@type":["LegalService","Organization"],"@id":"https://www.example-legal.co.uk/#org","address":{"@type":"PostalAddress","postalCode":"AB1 2CD"}}]}</script>'
			. '<script type="application/ld+json">[{"@context":"https://schema.org","@type":"BreadcrumbList","itemListElement":[]},{"@context":"https://schema.org","@type":"ImageObject","url":"https://www.example-legal.co.uk/a.png"}]</script>';
		$out   = ( new Extractor() )->extract( $html );
		$graph = new Graph( $out['blocks'], 'https://www.example-legal.co.uk/' );
		$types = array();
		foreach ( $graph->nodes as $node ) {
			$types = array_merge( $types, $node['types'] );
		}
		sort( $types );
		check_same( array( 'BreadcrumbList', 'ImageObject', 'LegalService', 'Organization', 'PostalAddress', 'WebSite' ), $types, 'every type indexed' );
		check_same( 'schema_org', $graph->contexts[1], 'array members with schema.org context' );
	}
);

mltsa_test(
	'F4 deep nesting, oversized blocks and node floods return review within a time limit',
	static function () {
		$start = microtime( true );
		$deep  = str_repeat( '{"a":', 200 ) . '1' . str_repeat( '}', 200 );
		$out   = ( new Extractor() )->extract( '<script type="application/ld+json">' . $deep . '</script>' );
		check_same( 'error', $out['blocks'][0]['parse'], 'depth limit stops decode' );
		check( in_array( 'SYN-003', rule_ids( audit_html( '<script type="application/ld+json">' . $deep . '</script>' )['findings'] ), true ), 'SYN-003 review for depth' );

		$big = '{"@context":"https://schema.org","@type":"Thing","x":"' . str_repeat( 'a', Extractor::MAX_BLOCK_BYTES + 10 ) . '"}';
		$out = ( new Extractor() )->extract( '<script type="application/ld+json">' . $big . '</script>' );
		check_same( 'too_large', $out['blocks'][0]['parse'], 'size cap before decode' );
		check( strlen( $out['blocks'][0]['raw'] ) <= Extractor::MAX_STORED_BYTES, 'stored raw evidence capped' );

		$nodes = array();
		for ( $i = 0; $i < Graph::MAX_NODES + 500; $i++ ) {
			$nodes[] = array( '@type' => 'Thing', '@id' => '#n' . $i, 'sameAs' => array( '@id' => '#n' . ( $i + 1 ) ) );
		}
		$flood  = json_encode( array( '@context' => 'https://schema.org', '@graph' => $nodes ) );
		$result = audit_html( '<script type="application/ld+json">' . $flood . '</script>' );
		check( in_array( 'SYN-003', rule_ids( $result['findings'] ), true ), 'node cap reported' );
		check( microtime( true ) - $start < 20, 'finished within 20 seconds' );
	}
);

mltsa_test(
	'F4 @id reference cycles do not loop',
	static function () {
		$html = '<script type="application/ld+json">{"@context":"https://schema.org","@graph":[{"@type":"WebPage","@id":"#a","about":{"@id":"#b"}},{"@type":"Organization","@id":"#b","subjectOf":{"@id":"#a"},"name":"Example Legal"}]}</script><p>Example Legal</p>';
		$out   = ( new Extractor() )->extract( $html );
		$graph = new Graph( $out['blocks'], 'https://www.example-legal.co.uk/' );
		$seen  = array();
		$a     = $graph->resolve( array( '@id' => '#a' ), $seen );
		$b     = $graph->resolve( array( '@id' => '#a' ), $seen );
		check_same( 1, count( $a ), 'resolved once' );
		check_same( 0, count( $b ), 'second visit stopped' );
		audit_html( $html );
	}
);

mltsa_test(
	'F5 a remote @context is never fetched and is reported as unsupported',
	static function () {
		$html   = '<script type="application/ld+json">{"@context":"https://attacker.example.net/context.jsonld","@type":"Organization","name":"X"}</script>';
		$result = audit_html( $html );
		$found  = null;
		foreach ( $result['findings'] as $f ) {
			if ( 'SYN-005' === $f['rule_id'] ) {
				$found = $f;
			}
		}
		check( null !== $found, 'SYN-005 reported' );
		check_same( 'review', $found['outcome'], 'unsupported context is a review, not a fail' );
		// The engine has no transport at all: extraction and evaluation cannot make requests.
		foreach ( array( 'Extractor', 'Graph', 'Evaluator', 'Rules', 'PageFacts' ) as $class ) {
			$source = file_get_contents( MLTSA_DIR . 'includes/Engine/' . $class . '.php' );
			check( ! preg_match( '/wp_remote_|wp_safe_remote|curl_exec|file_get_contents\s*\(|fopen\s*\(/', $source ), $class . ' makes no requests' );
		}
		check_same( 'schema_org', Graph::context_status( 'http://schema.org/' ), 'http schema.org accepted' );
		check_same( 'schema_org', Graph::context_status( array( '@vocab' => 'https://schema.org/' ) ), '@vocab accepted' );
		check_same( 'missing', Graph::context_status( null ), 'missing' );
	}
);

mltsa_test(
	'Extraction: canonical, robots, title, microdata and RDFa detected; page text excludes every script',
	static function () {
		$html = '<html><head><title>Conveyancing &amp; Property | Example</title><link rel="canonical" href="https://www.example-legal.co.uk/conveyancing/"><meta name="robots" content="noindex, follow">'
			. '<script type="application/ld+json">{"@context":"https://schema.org","@type":"LegalService","telephone":"01632 960001"}</script></head>'
			. '<body><div itemscope itemtype="https://schema.org/Person"><span itemprop="name">P</span></div><div vocab="https://schema.org/" typeof="Person"></div><p>Call us</p><script>var t="01632 960002";</script></body></html>';
		$out = ( new Extractor() )->extract( $html );
		check_same( 'https://www.example-legal.co.uk/conveyancing/', $out['canonical'], 'canonical' );
		check_same( 'noindex, follow', $out['robots'], 'robots' );
		check_same( 'Conveyancing & Property | Example', $out['title'], 'title' );
		check_same( 1, $out['microdata'], 'microdata' );
		check( $out['rdfa'] >= 1, 'RDFa' );
		check( false === strpos( $out['text'], '01632' ), 'no phone from JSON-LD or scripts in page text' );
	}
);

mltsa_test(
	'Extraction: canonical JSON ignores key order and whitespace but keeps array order',
	static function () {
		$a = Extractor::canonical_json( json_decode( '{"b":1,"a":[1,2]}', true ) );
		$b = Extractor::canonical_json( json_decode( "{ \"a\" : [1, 2],\n \"b\" : 1 }", true ) );
		$c = Extractor::canonical_json( json_decode( '{"b":1,"a":[2,1]}', true ) );
		check_same( $a, $b, 'formatting and key order ignored' );
		check( $a !== $c, 'array order significant' );
	}
);

mltsa_test(
	'Review 8: JSON-LD in comments and other inert contexts is not markup; real scripts around them still are',
	static function () {
		$ld   = '<script type="application/ld+json">{"@context":"https://schema.org","@type":"%s","name":"X"}</script>';
		$live = sprintf( $ld, 'LegalService' );
		$only = static function ( $html ) {
			return ( new Extractor() )->extract( $html )['blocks'];
		};

		check_same( 0, count( $only( '<body><!-- ' . sprintf( $ld, 'Organization' ) . ' --></body>' ) ), 'HTML comment' );
		check_same( 0, count( $only( '<body><!--' . sprintf( $ld, 'Organization' ) ) ), 'Unterminated comment runs to the end' );
		check_same( 0, count( $only( '<textarea>' . sprintf( $ld, 'Organization' ) . '</textarea>' ) ), 'textarea example' );
		check_same( 0, count( $only( '<TEXTAREA rows=3>' . sprintf( $ld, 'Organization' ) . '</TEXTAREA >' ) ), 'textarea, odd case' );
		check_same( 0, count( $only( '<template><div>' . sprintf( $ld, 'Organization' ) . '</div></template>' ) ), 'template' );
		check_same( 0, count( $only( '<template><template></template>' . sprintf( $ld, 'Organization' ) . '</template>' ) ), 'nested template' );
		check_same( 0, count( $only( '<noscript>' . sprintf( $ld, 'Organization' ) . '</noscript>' ) ), 'noscript' );
		check_same( 0, count( $only( '<xmp>' . sprintf( $ld, 'Organization' ) . '</xmp>' ) ), 'xmp' );
		check_same( 0, count( $only( '<body><plaintext>' . sprintf( $ld, 'Organization' ) ) ), 'plaintext' );
		check_same( 0, count( $only( '<title>' . sprintf( $ld, 'Organization' ) . '</title>' ) ), 'title' );
		check_same( 0, count( $only( '<div data-x="' . htmlspecialchars( sprintf( $ld, 'Organization' ) ) . '"></div><p title=\'<script type="application/ld+json">{}</script>\'>x</p>' ) ), 'Script text inside an attribute value' );

		// A comment or inert element does not hide the real block next to it.
		$blocks = $only( '<!-- ' . sprintf( $ld, 'Organization' ) . ' -->' . $live . '<textarea>' . sprintf( $ld, 'Person' ) . '</textarea>' . '<template></template>' );
		check_same( 1, count( $blocks ), 'Only the live block' );
		check_same( 'LegalService', $blocks[0]['data']['@type'], 'The live block is the one kept' );

		// A comment closed with --!> or an empty comment ends where a browser ends it.
		check_same( 1, count( $only( '<!--x--!>' . $live ) ), 'Comment closed by --!>' );
		check_same( 1, count( $only( '<!-->' . $live ) ), 'Empty comment <!-->' );

		// A ">" inside a quoted attribute does not end the script tag early.
		$blocks = $only( '<script data-note="a > b" type="application/ld+json">{"@context":"https://schema.org","@type":"LegalService"}</script>' );
		check_same( 1, count( $blocks ), 'Quoted ">" in a script attribute' );
		check_same( 'ok', $blocks[0]['parse'], 'and the content is the JSON, not the rest of the tag' );

		// Raw text rules inside a real script are unchanged: "<" and comment markers in the JSON are content.
		$blocks = $only( '<script type="application/ld+json">{"@context":"https://schema.org","@type":"LegalService","description":"a <!-- b <textarea> c"}</script>' );
		check_same( 'ok', $blocks[0]['parse'], 'Markup-like text inside the JSON string' );

		// And the commented block no longer produces findings or corroboration.
		$result = audit_html( '<html><head><!-- ' . sprintf( $ld, 'LegalService' ) . ' --></head><body><p>Hello</p></body></html>' );
		check( ! in_array( 'SYN-001', rule_ids( $result['findings'] ), true ), 'No syntax finding from disabled markup' );
	}
);

mltsa_test(
	'Review ENG-1: a CDATA wrapper commented out with a block comment is removed',
	static function () {
		$json    = '{"@context":"https://schema.org","@type":"LegalService","name":"X"}';
		$wrapped = array(
			'block comments'       => "/* <![CDATA[ */\n{$json}\n/* ]]> */",
			'block, no spaces'     => "/*<![CDATA[*/{$json}/*]]>*/",
			'line comments'        => "//<![CDATA[\n{$json}\n//]]>",
			'plain CDATA'          => "<![CDATA[{$json}]]>",
			'inside HTML comment'  => "<!--\n/* <![CDATA[ */\n{$json}\n/* ]]> */\n-->",
		);
		foreach ( $wrapped as $label => $content ) {
			$blocks = ( new Extractor() )->extract( '<script type="application/ld+json">' . $content . '</script>' )['blocks'];
			check_same( 'ok', $blocks[0]['parse'], $label . ' parses' );
			check_same( 'LegalService', $blocks[0]['data']['@type'], $label . ' keeps the data' );
		}
	}
);

mltsa_test(
	'Review ENG-2: multi-valued properties split across definitions of one @id are combined; single-valued ones stay first-wins',
	static function () {
		$ch   = 'https://find-and-update.company-information.service.gov.uk/company/SC123456';
		$base = array( '@context' => 'https://schema.org', '@type' => 'LegalService', '@id' => 'https://www.example-legal.co.uk/#org' );
		$page = static function ( array $a, array $b ) use ( $base ) {
			return '<html><head><script type="application/ld+json">' . json_encode( $base + $a ) . '</script>'
				. '<script type="application/ld+json">' . json_encode( $base + $b ) . '</script></head>'
				. '<body><p>Example Legal, solicitors in Glasgow.</p></body></html>';
		};

		// The Companies House link is in the second block only, behind another sameAs there.
		$split = audit_html( $page( array( 'name' => 'Example Legal', 'sameAs' => array( 'https://www.facebook.com/examplelegal' ) ), array( 'sameAs' => array( 'https://www.linkedin.com/company/examplelegal', $ch ) ) ) );
		check( in_array( 'FACT-012', rule_ids( $split['findings'] ), true ), 'sameAs from the second definition is seen' );

		// A string in one block and a list in the other combine too.
		$mixed = audit_html( $page( array( 'name' => 'Example Legal', 'sameAs' => 'https://www.facebook.com/examplelegal' ), array( 'sameAs' => $ch ) ) );
		check( in_array( 'FACT-012', rule_ids( $mixed['findings'] ), true ), 'string and string combine' );

		// Single-valued properties keep their meaning: the first name wins and is still a string.
		$names = audit_html( $page( array( 'name' => 'Example Legal' ), array( 'name' => 'Other Name' ) ) );
		check( ! in_array( 'FACT-012', rule_ids( $names['findings'] ), true ), 'No company number, no FACT-012' );

		// The combining rule: first's values, then new ones; one distinct value keeps its shape.
		$combine = new ReflectionMethod( 'MLT\\SchemaAudit\\Engine\\Evaluator', 'combine_values' );
		if ( PHP_VERSION_ID < 80100 ) {
			$combine->setAccessible( true );
		}
		check_same( array( 'a', 'b', 'c' ), $combine->invoke( null, array( 'a', 'b' ), array( 'b', 'c' ) ), 'Lists combine without repeats' );
		check_same( array( 'a', 'b' ), $combine->invoke( null, 'a', 'b' ), 'Two strings become a list' );
		check_same( 'a', $combine->invoke( null, 'a', array( 'a' ) ), 'One distinct value keeps its shape' );
		check_same( array( array( '@type' => 'PostalAddress', 'postalCode' => 'G1 1AA' ), array( 'postalCode' => 'G2 2BB', '@type' => 'PostalAddress' ) ), $combine->invoke( null, array( '@type' => 'PostalAddress', 'postalCode' => 'G1 1AA' ), array( 'postalCode' => 'G2 2BB', '@type' => 'PostalAddress' ) ), 'Two address objects become a list' );
		check_same( array( '@type' => 'PostalAddress', 'postalCode' => 'G1 1AA' ), $combine->invoke( null, array( '@type' => 'PostalAddress', 'postalCode' => 'G1 1AA' ), array( 'postalCode' => 'G1 1AA', '@type' => 'PostalAddress' ) ), 'Same object in a different key order is one value' );
	}
);

mltsa_test(
	'Review BUG-1: extra staging hosts are matched as whole hosts, with subdomains, and are not regexes',
	static function () {
		$page = static function ( $host ) {
			return '<script type="application/ld+json">{"@context":"https://schema.org","@type":"LegalService","name":"X","image":"https://' . $host . '/logo.png"}</script>';
		};
		$ctx  = array( 'staging_patterns' => array( 'preview.partner-agency.co.uk', 'build.example-dev.net' ) );
		check( in_array( 'URL-001', rule_ids( audit_html( $page( 'preview.partner-agency.co.uk' ), 'https://www.example-legal.co.uk/', $ctx )['findings'] ), true ), 'stored host matches itself' );
		check( in_array( 'URL-001', rule_ids( audit_html( $page( 'a.preview.partner-agency.co.uk' ), 'https://www.example-legal.co.uk/', $ctx )['findings'] ), true ), 'a subdomain of the stored host matches, as the built-in suffix patterns do' );
		check( ! in_array( 'URL-001', rule_ids( audit_html( $page( 'xpreview.partner-agency.co.uk' ), 'https://www.example-legal.co.uk/', $ctx )['findings'] ), true ), 'a longer host that merely ends with the text does not match' );
		check( ! in_array( 'URL-001', rule_ids( audit_html( $page( 'buildxexample-dev.net' ), 'https://www.example-legal.co.uk/', $ctx )['findings'] ), true ), 'the dot is literal, not a wildcard' );
		check( ! in_array( 'URL-001', rule_ids( audit_html( $page( 'cdn.example.org' ), 'https://www.example-legal.co.uk/', $ctx )['findings'] ), true ), 'unrelated host not flagged' );
		check( in_array( 'URL-001', rule_ids( audit_html( $page( 'staging.example.org' ), 'https://www.example-legal.co.uk/', $ctx )['findings'] ), true ), 'built-in patterns still work alongside' );
	}
);
