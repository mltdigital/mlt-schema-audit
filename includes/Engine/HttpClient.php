<?php
/**
 * Transport seam for the fetcher, so tests can script responses.
 *
 * @package MLT\SchemaAudit
 */

namespace MLT\SchemaAudit\Engine;

defined( 'ABSPATH' ) || defined( 'MLTSA_TESTING' ) || exit;

/**
 * One GET request, no redirects followed, connection pinned to an address.
 */
interface HttpClient {

	/**
	 * Perform a single request.
	 *
	 * @param string $url       Absolute URL.
	 * @param string $pinned_ip Address the connection must use.
	 * @param array  $args      { timeout, max_bytes, user_agent, method }.
	 * @return array { status: int, headers: array (lower-case keys), body: string,
	 *                 error: string, error_code: string, pinned: bool, truncated: bool }
	 */
	public function request( $url, $pinned_ip, array $args );
}
