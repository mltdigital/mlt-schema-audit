<?php
/**
 * Fixed vocabularies and their plain-English labels (contract sections 5
 * and 6). Pure PHP, so exports and tests share one source.
 *
 * @package MLT\SchemaAudit
 */

namespace MLT\SchemaAudit;

defined( 'ABSPATH' ) || defined( 'MLTSA_TESTING' ) || exit;

/**
 * Labels.
 */
class Labels {

	/**
	 * Work statuses staff set.
	 */
	const WORK = array(
		'open'                   => 'Open',
		'in_progress'            => 'In progress',
		'awaiting_client'        => 'Awaiting client evidence',
		'ready_for_verification' => 'Ready for verification',
		'resolved'               => 'Resolved',
		'accepted_exception'     => 'Accepted exception',
		'false_positive'         => 'False positive',
	);

	/**
	 * Work statuses that need a reason, a reviewer and a review date.
	 */
	const NEEDS_REASON = array( 'accepted_exception', 'false_positive' );

	/**
	 * Verification states only the scanner sets.
	 */
	const VERIFICATION = array(
		'present'            => 'Present',
		'changed'            => 'Changed',
		'returned'           => 'Returned',
		'no_longer_detected' => 'No longer detected',
		'page_removed'       => 'Page removed or redirected',
		'unavailable'        => 'Unavailable',
	);

	/**
	 * Run states.
	 */
	const RUN_STATES = array(
		'queued'    => 'Queued',
		'running'   => 'Running',
		'complete'  => 'Complete',
		'partial'   => 'Partial: some pages not read',
		'failed'    => 'Failed: no page read',
		'cancelled' => 'Cancelled',
		'purged'    => 'Evidence removed by retention',
	);

	/**
	 * Page coverage outcomes.
	 */
	const COVERAGE = array(
		'pending'        => 'Not read yet',
		'ok'             => 'Read',
		'excluded'       => 'Excluded',
		'redirected'     => 'Redirected',
		'not_found'      => 'Not found (404)',
		'gone'           => 'Gone (410)',
		'blocked'        => 'Blocked by the request policy',
		'timeout'        => 'Timed out',
		'too_large'      => 'Too large to read',
		'http_error'     => 'HTTP error',
		'redirect_limit' => 'Too many redirects',
		'unavailable'    => 'Unavailable',
		'not_html'       => 'Not an HTML page',
		'error'          => 'Error',
	);

	/**
	 * Outcomes.
	 */
	const OUTCOMES = array(
		'fail'           => 'Fail',
		'review'         => 'Review',
		'unavailable'    => 'Unavailable',
		'not_applicable' => 'Not applicable',
		'pass'           => 'Pass',
	);

	/**
	 * Severities, most severe first.
	 */
	const SEVERITIES = array(
		'critical' => 'Critical',
		'high'     => 'High',
		'medium'   => 'Medium',
		'low'      => 'Low',
		'info'     => 'Information',
	);

	/**
	 * The coverage statement every report and screen carries (section 4).
	 */
	const COVERAGE_STATEMENT = 'Server-response JSON-LD audit. Microdata and RDFa are detected but not validated. Markup added by JavaScript after the page loads is not seen. "No JSON-LD detected" does not mean "no structured data".';

	/**
	 * Label for a value in a vocabulary.
	 *
	 * @param array  $map   Vocabulary.
	 * @param string $value Value.
	 * @return string
	 */
	public static function of( array $map, $value ) {
		return isset( $map[ $value ] ) ? $map[ $value ] : (string) $value;
	}
}
