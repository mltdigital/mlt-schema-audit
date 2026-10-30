<?php
/**
 * The versioned rule catalogue.
 *
 * Every rule has a stable ID, a version, a group, a severity, a display
 * group, what it applies to, what evidence it needs, a source and a reviewed
 * date (contract section 5). Bump a rule's version whenever its logic
 * changes, and bump RULESET_VERSION with it, so a rule change is never
 * reported as a website change.
 *
 * Corrections from the plan (lines 89 to 99) are built in, not carried over:
 * a foreign @id is not invalid; a quoted ratingValue is allowed; image may be
 * a URL or an ImageObject; type inheritance is honoured; self-serving reviews
 * are an eligibility restriction, not invalid markup; absent optional
 * properties are not defects; repeated @ids are allowed unless values conflict.
 *
 * @package MLT\SchemaAudit
 */

namespace MLT\SchemaAudit\Engine;

defined( 'ABSPATH' ) || defined( 'MLTSA_TESTING' ) || exit;

/**
 * Rules.
 */
class Rules {

	/**
	 * Rule-set version. Bump with any rule change.
	 */
	const RULESET_VERSION = '2026.10.1';

	/**
	 * Group labels.
	 */
	const GROUPS = array(
		'syntax'      => 'Syntax and structure',
		'identity'    => 'Identity and relationships',
		'facts'       => 'Published facts',
		'urls'        => 'URLs and resources',
		'features'    => 'Search feature requirements',
		'relevance'   => 'Relevance and completeness',
		'consistency' => 'Site consistency',
	);

	/**
	 * Display group labels.
	 */
	const DISPLAY = array(
		'confirmed'   => 'Confirmed errors',
		'conflict'    => 'Potential conflicts',
		'eligibility' => 'Eligibility restrictions',
		'optional'    => 'Optional improvements',
	);

	/**
	 * The catalogue.
	 *
	 * @return array
	 */
	public static function catalogue() {
		$json_ld   = 'https://www.w3.org/TR/json-ld11/';
		$schema    = 'https://schema.org/docs/datamodel.html';
		$google    = 'https://developers.google.com/search/docs/appearance/structured-data/sd-policies';
		$reviewed  = '2026-10-30';
		$rules     = array(
			'SYN-001'  => array( 1, 'syntax', 'high', 'confirmed', 'JSON-LD block does not parse', 'Every application/ld+json block in the server response.', 'Block index and the parser\'s original error.', $json_ld, 'The block is not valid JSON, so search engines ignore all of it.', 'Open the page source, find the block by its position, and correct the JSON at the point the error names. Check which plugin or widget outputs it.' ),
			'SYN-002'  => array( 1, 'syntax', 'high', 'confirmed', 'JSON-LD block is HTML entity encoded', 'Blocks that fail to parse but parse after entity decoding.', 'Original error and the decoded form.', $json_ld, 'Script content is read literally, so &quot; is not a quote mark. The block is invalid as published even though it looks right in an editor.', 'Find the widget or field that escapes the markup (often a page builder HTML widget) and output the JSON unescaped.' ),
			'SYN-003'  => array( 1, 'syntax', 'medium', 'conflict', 'Block too large or too deeply nested to analyse', 'Blocks over the size, depth or node limits.', 'Block size or depth reached.', $json_ld, 'The audit stopped analysing this block at a safety limit, so its findings are incomplete. This is not proof the markup is wrong.', 'Check whether the block is generated in a loop or duplicates content.' ),
			'SYN-004'  => array( 1, 'syntax', 'low', 'confirmed', 'Empty JSON-LD block', 'Script blocks typed application/ld+json.', 'Block index.', $json_ld, 'An empty block publishes nothing.', 'Find what outputs the empty block and remove it or fill it.' ),
			'SYN-005'  => array( 1, 'syntax', 'medium', 'confirmed', 'Missing or unsupported @context', 'Parsed blocks.', 'The @context value.', $json_ld, 'Without a schema.org @context the types and properties have no agreed meaning. Remote contexts other than schema.org are never fetched, so they are reported, not interpreted.', 'Set "@context": "https://schema.org" on the block.' ),
			'SYN-006'  => array( 1, 'syntax', 'low', 'conflict', 'Top-level entity without @type', 'Top-level objects in parsed blocks.', 'JSON path.', $schema, 'An entity with no type cannot be matched to any schema.org definition.', 'Add the intended @type.' ),
			'SYN-007'  => array( 1, 'syntax', 'low', 'conflict', 'Type name not in schema.org form', 'Every @type value.', 'The type string.', $schema, 'schema.org type names are case-sensitive words such as LegalService. A misspelt or lower-case type is not recognised.', 'Correct the type name against schema.org.' ),
			'ID-001'   => array( 1, 'identity', 'high', 'conflict', 'Same @id with conflicting values on one page', 'Entities sharing an @id on the page.', 'Both values and their block paths.', $json_ld, 'Repeating an @id to add properties is legitimate, but here two definitions disagree on the same property, so consumers cannot tell which is true.', 'Find both blocks (often an SEO plugin and a second source) and make one authoritative.' ),
			'ID-002'   => array( 1, 'identity', 'high', 'conflict', 'Primary business identity on another website', 'Business entities presented as the page\'s own organisation.', 'The @id or url host, and the site host.', $json_ld, 'A foreign @id is valid JSON-LD, but the business this page presents as its own is identified on another site. That has historically meant another firm\'s details leaking into the markup.', 'Confirm whether the entity is this firm. If it is, use an @id on this site; if it is a third party, link it as such rather than as publisher or provider.' ),
			'ID-003'   => array( 1, 'identity', 'low', 'optional', 'Reference to an entity not defined on the page', 'References to @id values on the site\'s own host.', 'The unresolved @id.', $json_ld, 'The page points to an entity by @id but never defines it, so the relationship carries no facts.', 'Define the entity on the page or point to the @id the site actually uses.' ),
			'FACT-001' => array( 1, 'facts', 'medium', 'conflict', 'Telephone not found on the page', 'Telephone values on businesses, places and contact points.', 'The schema value and the numbers found in the page text and tel: links.', $google, 'The number in the markup is not corroborated by the page. It may be correct but unpublished, or it may be wrong. This is not proof it is invented.', 'Check the number against the firm\'s published contact details.' ),
			'FACT-002' => array( 1, 'facts', 'medium', 'conflict', 'Postcode not found on the page', 'postalCode values on addresses.', 'The schema value and the postcodes found in the page text.', $google, 'The postcode in the markup is not corroborated by the page.', 'Check the postcode against the office address.' ),
			'FACT-003' => array( 1, 'facts', 'high', 'conflict', 'Business name not found on the page', 'name on business entities.', 'The schema value and the page title.', $google, 'The business named in the markup does not appear on the page. This is how the historical wrong-firm cases showed up.', 'Confirm the markup names this firm. Check for copied templates from another site.' ),
			'FACT-004' => array( 1, 'facts', 'medium', 'confirmed', 'Telephone value is not a usable number', 'Telephone values.', 'The schema value.', 'https://schema.org/telephone', 'The value cannot be dialled as a UK or international number.', 'Correct the telephone value.' ),
			'FACT-005' => array( 1, 'facts', 'medium', 'conflict', 'Person not found on the page', 'Person entities that are a profile page\'s main subject.', 'The schema name and the page title.', $google, 'The person described in the markup is not named on the page, which can mean a copied profile template.', 'Check the profile markup names the person the page is about.' ),
			'FACT-006' => array( 1, 'facts', 'high', 'conflict', 'Telephone not in the approved fact reference', 'Telephone values, when staff have set approved numbers.', 'The schema value and the approved list.', $google, 'Staff recorded the firm\'s approved numbers, and this one is not among them.', 'Check the number with the client, then correct the markup or the reference.' ),
			'URL-001'  => array( 1, 'urls', 'high', 'confirmed', 'Staging or development address in published markup', 'Every URL value.', 'The URL and the matching pattern.', $google, 'The live markup points to a staging or development host, which the public cannot reach.', 'Replace the staging host with the live one. Search the source plugin\'s settings for the old address.' ),
			'URL-002'  => array( 1, 'urls', 'low', 'optional', 'Site URL uses http on an https site', 'URL values on the site\'s own host.', 'The URL.', $google, 'The value works through a redirect, but the markup and the live site disagree about the address.', 'Use the https address.' ),
			'URL-003'  => array( 1, 'urls', 'medium', 'conflict', 'WebPage url differs from the canonical URL', 'WebPage entities with a url, on pages with a canonical link.', 'Both URLs.', 'https://developers.google.com/search/docs/crawling-indexing/consolidate-duplicate-urls', 'The markup describes a different address from the one the page declares canonical.', 'Check which address is right and correct the other.' ),
			'URL-004'  => array( 1, 'urls', 'medium', 'confirmed', 'Image or logo on this site returns not found', 'image, logo and contentUrl values on the site\'s own host.', 'The URL and its HTTP status (404 or 410 only).', $google, 'The markup cites a file that no longer exists. Timeouts and blocks are reported as unavailable, not as broken.', 'Upload the file again or point the markup at the current file.' ),
			'URL-005'  => array( 1, 'urls', 'low', 'conflict', 'Malformed URL value', 'URL-typed properties.', 'The value.', 'https://schema.org/URL', 'The value is not a usable absolute URL (spaces, an encoded &amp;, or no scheme).', 'Correct the URL in the source field.' ),
			'FEAT-001' => array( 1, 'features', 'medium', 'eligibility', 'Ratings on the firm\'s own business entity', 'aggregateRating or review on the site\'s own business.', 'The rating values.', 'https://developers.google.com/search/docs/appearance/structured-data/review-snippet', 'Google does not show review stars for reviews a business publishes about itself. The markup is valid; it is not eligible for that feature. It is not a ranking penalty.', 'Decide with the client whether to keep it. Do not describe it to the client as an error.' ),
			'FEAT-002' => array( 1, 'features', 'medium', 'confirmed', 'FAQPage with no questions', 'FAQPage entities.', 'The mainEntity value.', 'https://developers.google.com/search/docs/appearance/structured-data/faqpage', 'An FAQPage must list its questions in mainEntity. This one lists none.', 'Remove the FAQPage type or add the questions shown on the page.' ),
			'FEAT-003' => array( 1, 'features', 'medium', 'eligibility', 'FAQ question not visible on the page', 'Question entities under an FAQPage.', 'The question text.', 'https://developers.google.com/search/docs/appearance/structured-data/faqpage', 'FAQ markup must match questions users can see on the page.', 'Show the question on the page or remove it from the markup.' ),
			'FEAT-004' => array( 1, 'features', 'medium', 'eligibility', 'Rating missing a required value', 'AggregateRating entities.', 'ratingValue, ratingCount and reviewCount.', 'https://developers.google.com/search/docs/appearance/structured-data/review-snippet', 'A rating needs ratingValue and a count. A quoted number such as "4.8" is allowed; text that is not a number is not.', 'Add the missing value or remove the rating.' ),
			'FEAT-005' => array( 1, 'features', 'low', 'eligibility', 'Breadcrumb item incomplete', 'ListItem entities in a BreadcrumbList.', 'The list item.', 'https://developers.google.com/search/docs/appearance/structured-data/breadcrumb', 'Each breadcrumb item needs a position and a name, and every item except the last needs a URL.', 'Correct the breadcrumb settings in the source plugin.' ),
			'FEAT-006' => array( 1, 'features', 'low', 'confirmed', 'Image value is neither a URL nor an image object', 'image and logo values.', 'The value.', 'https://schema.org/image', 'image accepts a URL or an ImageObject. This value is neither.', 'Use a URL or an ImageObject with url or contentUrl.' ),
			'FEAT-007' => array( 1, 'features', 'low', 'eligibility', 'Local business without an address', 'LocalBusiness and its subtypes, including LegalService.', 'The entity.', 'https://developers.google.com/search/docs/appearance/structured-data/local-business', 'Google\'s local business feature requires an address. Organization alone does not, and multiple offices do not need to be on every page.', 'Add the office address, or use Organization if no office is meant.' ),
			'REL-001'  => array( 1, 'relevance', 'info', 'optional', 'No JSON-LD in the server response', 'Every page fetched.', 'Block count and other formats seen.', $google, 'No JSON-LD was found in the HTML the server returned. Markup added later by JavaScript is not seen by this audit, so this is not proof the page has no structured data.', 'Decide whether this page should carry markup.' ),
			'REL-002'  => array( 1, 'relevance', 'info', 'optional', 'Microdata or RDFa present, not validated', 'Every page fetched.', 'Counts of itemscope and typeof/vocab attributes.', $google, 'This release detects Microdata and RDFa but does not validate them.', 'Check these formats with another tool if they matter on this page.' ),
			'SITE-001' => array( 1, 'consistency', 'high', 'confirmed', 'Same business @id with different details on different pages', 'Business entities sharing an @id across pages.', 'Each value and the pages it appears on.', $json_ld, 'One business identifier carries different phone numbers, postcodes or names on different pages, so the site contradicts itself about one entity. Separate branches should have separate @ids.', 'Decide which value is right for this entity. If they are different offices, give each its own @id.' ),
		);
		$out = array();
		foreach ( $rules as $id => $r ) {
			$out[ $id ] = array(
				'id'          => $id,
				'version'     => $r[0],
				'group'       => $r[1],
				'severity'    => $r[2],
				'display'     => $r[3],
				'title'       => $r[4],
				'applies'     => $r[5],
				'evidence'    => $r[6],
				'source'      => $r[7],
				'reviewed'    => $reviewed,
				'explanation' => $r[8],
				'investigate' => $r[9],
			);
		}
		return $out;
	}

	/**
	 * One rule.
	 *
	 * @param string $id Rule ID.
	 * @return array|null
	 */
	public static function get( $id ) {
		$all = self::catalogue();
		return isset( $all[ $id ] ) ? $all[ $id ] : null;
	}

	/**
	 * Rule ID => version, stored on each run so comparisons can tell a rule
	 * change from a website change.
	 *
	 * @return array
	 */
	public static function fingerprint() {
		$out = array();
		foreach ( self::catalogue() as $id => $rule ) {
			$out[ $id ] = (int) $rule['version'];
		}
		return $out;
	}
}
