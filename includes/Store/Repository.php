<?php
/**
 * Every database read and write the plugin makes, in one class.
 *
 * Only the seven mltsa_ tables are touched (contract section 1, A6). Every
 * query with a variable goes through $wpdb->prepare() (A5). Table names come
 * from Installer::TABLES, never from input, which is why the interpolation
 * sniff is disabled for this file only.
 *
 * @package MLT\SchemaAudit
 */

namespace MLT\SchemaAudit\Store;

use MLT\SchemaAudit\Installer;

defined( 'ABSPATH' ) || exit;

// phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Table names are fixed strings from Installer::TABLES.
// phpcs:disable WordPress.DB.DirectDatabaseQuery -- The plugin's own tables have no WordPress API; results are not cached because audits must read current state.

/**
 * Repository.
 */
class Repository {

	/**
	 * Run states that are still in progress.
	 */
	const ACTIVE_RUN_STATES = array( 'queued', 'running' );

	/**
	 * Table name.
	 *
	 * @param string $suffix Suffix.
	 * @return string
	 */
	private function t( $suffix ) {
		return Installer::table( $suffix );
	}

	/**
	 * Current UTC time in MySQL form.
	 *
	 * @return string
	 */
	public static function now() {
		return gmdate( 'Y-m-d H:i:s' );
	}

	/**
	 * Decode a JSON column.
	 *
	 * @param string $json JSON.
	 * @return array
	 */
	public static function decode( $json ) {
		$data = json_decode( (string) $json, true );
		return is_array( $data ) ? $data : array();
	}

	/* ------------------------------------------------------------------ Runs */

	/**
	 * Create a run. Returns 0 when the schedule key already exists (S2).
	 *
	 * @param array $fields Fields.
	 * @return int
	 */
	public function create_run( array $fields ) {
		global $wpdb;
		$fields = array_merge(
			array(
				'run_type'        => 'manual',
				'trigger_type'    => 'user',
				'trigger_user'    => 0,
				'schedule_key'    => null,
				'scope'           => '{}',
				'engine_version'  => MLTSA_ENGINE_VERSION,
				'ruleset_version' => \MLT\SchemaAudit\Engine\Rules::RULESET_VERSION,
				'fingerprint'     => wp_json_encode( \MLT\SchemaAudit\Engine\Rules::fingerprint() ),
				'state'           => 'queued',
				'phase'           => 'discover',
				'created_utc'     => self::now(),
				'summary'         => '{}',
			),
			$fields
		);
		if ( null !== $fields['schedule_key'] && $this->run_by_schedule_key( $fields['schedule_key'] ) ) {
			return 0;
		}
		$suppress = $wpdb->suppress_errors( true );
		$ok       = $wpdb->insert( $this->t( 'runs' ), $fields );
		$wpdb->suppress_errors( $suppress );
		return $ok ? (int) $wpdb->insert_id : 0;
	}

	/**
	 * One run.
	 *
	 * @param int $id Run ID.
	 * @return array|null
	 */
	public function get_run( $id ) {
		global $wpdb;
		$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$this->t( 'runs' )} WHERE id = %d", (int) $id ), ARRAY_A );
		return $row ? $row : null;
	}

	/**
	 * Run for a schedule key.
	 *
	 * @param string $key Key.
	 * @return array|null
	 */
	public function run_by_schedule_key( $key ) {
		global $wpdb;
		$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$this->t( 'runs' )} WHERE schedule_key = %s", (string) $key ), ARRAY_A );
		return $row ? $row : null;
	}

	/**
	 * Update a run.
	 *
	 * @param int   $id     Run ID.
	 * @param array $fields Fields.
	 */
	public function update_run( $id, array $fields ) {
		global $wpdb;
		$wpdb->update( $this->t( 'runs' ), $fields, array( 'id' => (int) $id ) );
	}

	/**
	 * Update a run only while it is still in the given state, in one
	 * statement, so a cancel saved while a worker was part way through a
	 * step is never written over.
	 *
	 * @param int    $id     Run ID.
	 * @param string $state  State the run must be in.
	 * @param array  $fields Fields.
	 * @return bool Whether a row was changed (reliable when $fields changes the state).
	 */
	public function update_run_in_state( $id, $state, array $fields ) {
		global $wpdb;
		$changed = $wpdb->update(
			$this->t( 'runs' ),
			$fields,
			array(
				'id'    => (int) $id,
				'state' => (string) $state,
			)
		);
		return false !== $changed && $changed > 0;
	}

	/**
	 * Cancel a run that is still queued or running. A run that finished
	 * meanwhile keeps its outcome, and so does one that has already written
	 * its results to the issue register (phase notify): cancelling it then
	 * would leave the register changed by a cancelled run (branch review R4).
	 *
	 * @param int $id Run ID.
	 * @return bool Whether the run was cancelled.
	 */
	public function cancel_run( $id ) {
		global $wpdb;
		$changed = $wpdb->query( $wpdb->prepare( "UPDATE {$this->t( 'runs' )} SET state = 'cancelled', phase = 'done', finished_utc = %s WHERE id = %d AND state IN ('queued','running') AND phase <> 'notify'", self::now(), (int) $id ) );
		return false !== $changed && $changed > 0;
	}

	/**
	 * Start a transaction (InnoDB on MySQL and MariaDB; SQLite on the
	 * development site). MyISAM tables ignore it.
	 */
	public function begin() {
		global $wpdb;
		$wpdb->query( 'START TRANSACTION' ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Groups one step's writes.
	}

	/**
	 * Commit the transaction begin() started.
	 */
	public function commit() {
		global $wpdb;
		$wpdb->query( 'COMMIT' ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Groups one step's writes.
	}

	/**
	 * Undo the transaction begin() started.
	 */
	public function rollback() {
		global $wpdb;
		$wpdb->query( 'ROLLBACK' ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Groups one step's writes.
	}

	/**
	 * A run's state, read fresh.
	 *
	 * @param int $id Run ID.
	 * @return string Empty when the run does not exist.
	 */
	public function run_state( $id ) {
		global $wpdb;
		return (string) $wpdb->get_var( $wpdb->prepare( "SELECT state FROM {$this->t( 'runs' )} WHERE id = %d", (int) $id ) );
	}

	/**
	 * The run in progress, if any (oldest first).
	 *
	 * @return array|null
	 */
	public function active_run() {
		global $wpdb;
		$row = $wpdb->get_row( "SELECT * FROM {$this->t( 'runs' )} WHERE state IN ('queued','running') ORDER BY id ASC LIMIT 1", ARRAY_A );
		return $row ? $row : null;
	}

	/**
	 * Recent runs.
	 *
	 * @param int $limit  Limit.
	 * @param int $offset Offset.
	 * @return array
	 */
	public function runs( $limit = 20, $offset = 0 ) {
		global $wpdb;
		return (array) $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$this->t( 'runs' )} ORDER BY id DESC LIMIT %d OFFSET %d", (int) $limit, (int) $offset ), ARRAY_A );
	}

	/**
	 * Number of runs.
	 *
	 * @return int
	 */
	public function count_runs() {
		global $wpdb;
		return (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$this->t( 'runs' )}" );
	}

	/**
	 * Take the run's processing lock if it is free or expired (S2).
	 *
	 * @param int    $id    Run ID.
	 * @param string $token Lock token.
	 * @param int    $ttl   Seconds.
	 * @return bool
	 */
	public function claim_run( $id, $token, $ttl ) {
		global $wpdb;
		$now = time();
		$wpdb->query( $wpdb->prepare( "UPDATE {$this->t( 'runs' )} SET lock_token = %s, lock_expires = %d WHERE id = %d AND (lock_token = '' OR lock_expires < %d)", $token, $now + (int) $ttl, (int) $id, $now ) );
		$held = $wpdb->get_var( $wpdb->prepare( "SELECT lock_token FROM {$this->t( 'runs' )} WHERE id = %d", (int) $id ) );
		return $held === $token;
	}

	/**
	 * Release the run's lock if this token holds it.
	 *
	 * @param int    $id    Run ID.
	 * @param string $token Token.
	 */
	public function release_run( $id, $token ) {
		global $wpdb;
		$wpdb->query( $wpdb->prepare( "UPDATE {$this->t( 'runs' )} SET lock_token = '', lock_expires = 0 WHERE id = %d AND lock_token = %s", (int) $id, $token ) );
	}

	/**
	 * The run a new run compares with: the last complete or partial run of
	 * a comparable type before it. Monthly runs compare only with monthly
	 * runs. A partial baseline is safe because comparison works page by page
	 * and only a page read in both runs can show an issue as resolved.
	 *
	 * @param array $run Run row.
	 * @return array|null
	 */
	public function baseline_for( array $run ) {
		global $wpdb;
		$types = 'monthly' === $run['run_type'] ? array( 'monthly' ) : array( 'monthly', 'manual' );
		$in    = implode( ',', array_fill( 0, count( $types ), '%s' ) );
		$args  = array_merge( array( (int) $run['id'] ), $types );
		$row   = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$this->t( 'runs' )} WHERE id < %d AND state IN ('complete','partial') AND run_type IN ($in) ORDER BY id DESC LIMIT 1", $args ), ARRAY_A ); // phpcs:ignore WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare -- $in is a list of %s placeholders.
		return $row ? $row : null;
	}

	/**
	 * Summary of the most recent run before this one that finished its
	 * comparison (complete, partial or failed), of any type.
	 *
	 * @param int $run_id Run ID.
	 * @return array
	 */
	public function previous_finished_summary( $run_id ) {
		global $wpdb;
		$summary = $wpdb->get_var( $wpdb->prepare( "SELECT summary FROM {$this->t( 'runs' )} WHERE id < %d AND state IN ('complete','partial','failed') ORDER BY id DESC LIMIT 1", (int) $run_id ) );
		return self::decode( (string) $summary );
	}

	/* -------------------------------------------------------------- Run URLs */

	/**
	 * Add a URL to a run's frozen list.
	 *
	 * @param array $fields Fields.
	 * @return int
	 */
	public function insert_run_url( array $fields ) {
		global $wpdb;
		$fields = array_merge(
			array(
				'redirect_chain' => '[]',
				'title'          => '',
				'facts'          => '{}',
			),
			$fields
		);
		$wpdb->insert( $this->t( 'run_urls' ), $fields );
		return (int) $wpdb->insert_id;
	}

	/**
	 * Save a run's frozen URL list, replacing any rows an earlier attempt
	 * left behind. Discovery saves the list in its last step and then moves
	 * the run to the fetch phase; a worker killed in between left the rows
	 * saved and the run still in discovery, so the next attempt added every
	 * URL again. One transaction where the database supports it, so a kill
	 * part way through leaves no partial list either.
	 *
	 * @param int   $run_id Run ID.
	 * @param array $rows   Field arrays for insert_run_url(), without run_id.
	 */
	public function replace_run_urls( $run_id, array $rows ) {
		global $wpdb;
		$wpdb->query( 'START TRANSACTION' ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Groups the list into one write.
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$this->t( 'run_urls' )} WHERE run_id = %d", (int) $run_id ) );
		foreach ( $rows as $fields ) {
			$this->insert_run_url( array( 'run_id' => (int) $run_id ) + $fields );
		}
		$wpdb->query( 'COMMIT' ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Groups the list into one write.
	}

	/**
	 * Update a run URL.
	 *
	 * @param int   $id     ID.
	 * @param array $fields Fields.
	 */
	public function update_run_url( $id, array $fields ) {
		global $wpdb;
		$wpdb->update( $this->t( 'run_urls' ), $fields, array( 'id' => (int) $id ) );
	}

	/**
	 * Next URLs waiting to be fetched, in list order.
	 *
	 * @param int $run_id Run ID.
	 * @param int $limit  Limit.
	 * @return array
	 */
	public function pending_urls( $run_id, $limit ) {
		global $wpdb;
		return (array) $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$this->t( 'run_urls' )} WHERE run_id = %d AND coverage = 'pending' ORDER BY seq ASC LIMIT %d", (int) $run_id, (int) $limit ), ARRAY_A );
	}

	/**
	 * One run URL, checked against its run (A4).
	 *
	 * @param int $run_id Run ID.
	 * @param int $id     Run URL ID.
	 * @return array|null
	 */
	public function get_run_url( $run_id, $id ) {
		global $wpdb;
		$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$this->t( 'run_urls' )} WHERE run_id = %d AND id = %d", (int) $run_id, (int) $id ), ARRAY_A );
		return $row ? $row : null;
	}

	/**
	 * Coverage counts for a run.
	 *
	 * @param int $run_id Run ID.
	 * @return array coverage => count
	 */
	public function coverage_counts( $run_id ) {
		global $wpdb;
		$rows = (array) $wpdb->get_results( $wpdb->prepare( "SELECT coverage, COUNT(*) AS n FROM {$this->t( 'run_urls' )} WHERE run_id = %d GROUP BY coverage", (int) $run_id ), ARRAY_A );
		$out  = array();
		foreach ( $rows as $row ) {
			$out[ $row['coverage'] ] = (int) $row['n'];
		}
		return $out;
	}

	/**
	 * Run URLs, paged.
	 *
	 * @param int    $run_id   Run ID.
	 * @param int    $limit    Limit.
	 * @param int    $offset   Offset.
	 * @param string $coverage Optional coverage filter.
	 * @return array
	 */
	public function run_urls( $run_id, $limit = 100, $offset = 0, $coverage = '' ) {
		global $wpdb;
		if ( '' !== $coverage ) {
			return (array) $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$this->t( 'run_urls' )} WHERE run_id = %d AND coverage = %s ORDER BY seq ASC LIMIT %d OFFSET %d", (int) $run_id, $coverage, (int) $limit, (int) $offset ), ARRAY_A );
		}
		return (array) $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$this->t( 'run_urls' )} WHERE run_id = %d ORDER BY seq ASC LIMIT %d OFFSET %d", (int) $run_id, (int) $limit, (int) $offset ), ARRAY_A );
	}

	/**
	 * Coverage outcome by URL key, for reconciliation. Excluded URLs are
	 * left out, so an exclusion never sets "no longer detected".
	 *
	 * @param int $run_id Run ID.
	 * @return array url_key => coverage
	 */
	public function coverage_map( $run_id ) {
		global $wpdb;
		$rows = (array) $wpdb->get_results( $wpdb->prepare( "SELECT url, coverage, markup_hash FROM {$this->t( 'run_urls' )} WHERE run_id = %d AND coverage <> 'excluded'", (int) $run_id ), ARRAY_A );
		$out  = array();
		foreach ( $rows as $row ) {
			$out[ \MLT\SchemaAudit\Engine\Evaluator::url_key( $row['url'] ) ] = array(
				'coverage' => $row['coverage'],
				'markup'   => $row['markup_hash'],
			);
		}
		return $out;
	}

	/**
	 * Site facts for every page read in a run.
	 *
	 * @param int $run_id Run ID.
	 * @return array run_url_id => facts
	 */
	public function page_facts( $run_id ) {
		global $wpdb;
		$rows = (array) $wpdb->get_results( $wpdb->prepare( "SELECT id, facts FROM {$this->t( 'run_urls' )} WHERE run_id = %d AND coverage = 'ok'", (int) $run_id ), ARRAY_A );
		$out  = array();
		foreach ( $rows as $row ) {
			$out[ (int) $row['id'] ] = self::decode( $row['facts'] );
		}
		return $out;
	}

	/**
	 * URLs of a run by ID.
	 *
	 * @param int $run_id Run ID.
	 * @return array id => url
	 */
	public function url_index( $run_id ) {
		global $wpdb;
		$rows = (array) $wpdb->get_results( $wpdb->prepare( "SELECT id, url FROM {$this->t( 'run_urls' )} WHERE run_id = %d", (int) $run_id ), ARRAY_A );
		$out  = array();
		foreach ( $rows as $row ) {
			$out[ (int) $row['id'] ] = $row['url'];
		}
		return $out;
	}

	/* ---------------------------------------------------------------- Blocks */

	/**
	 * Store an observed block.
	 *
	 * @param array $fields Fields.
	 * @return int
	 */
	public function insert_block( array $fields ) {
		global $wpdb;
		$wpdb->insert( $this->t( 'blocks' ), $fields );
		return (int) $wpdb->insert_id;
	}

	/**
	 * Blocks for one page of a run.
	 *
	 * @param int $run_id     Run ID.
	 * @param int $run_url_id Run URL ID.
	 * @return array
	 */
	public function blocks_for( $run_id, $run_url_id ) {
		global $wpdb;
		return (array) $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$this->t( 'blocks' )} WHERE run_id = %d AND run_url_id = %d ORDER BY block_index ASC", (int) $run_id, (int) $run_url_id ), ARRAY_A );
	}

	/* ----------------------------------------------------------- Occurrences */

	/**
	 * Store a rule outcome.
	 *
	 * @param array $fields Fields.
	 * @return int
	 */
	public function insert_occurrence( array $fields ) {
		global $wpdb;
		$wpdb->insert( $this->t( 'occurrences' ), $fields );
		return (int) $wpdb->insert_id;
	}

	/**
	 * Every occurrence in a run, keyed by issue key (first wins), with the
	 * page URL it was observed on.
	 *
	 * @param int $run_id Run ID.
	 * @return array issue_key => row (plus page_url)
	 */
	public function occurrences_by_key( $run_id ) {
		global $wpdb;
		$rows = (array) $wpdb->get_results( $wpdb->prepare( "SELECT o.*, u.url AS page_url FROM {$this->t( 'occurrences' )} o LEFT JOIN {$this->t( 'run_urls' )} u ON u.id = o.run_url_id WHERE o.run_id = %d ORDER BY o.id ASC", (int) $run_id ), ARRAY_A );
		$out  = array();
		foreach ( $rows as $row ) {
			if ( ! isset( $out[ $row['issue_key'] ] ) ) {
				$row['page_url']          = (string) $row['page_url'];
				$out[ $row['issue_key'] ] = $row;
			}
		}
		return $out;
	}

	/**
	 * One occurrence with its page.
	 *
	 * @param int $id Occurrence ID.
	 * @return array|null
	 */
	public function occurrence( $id ) {
		global $wpdb;
		$row = $wpdb->get_row( $wpdb->prepare( "SELECT o.*, u.url AS page_url, u.title AS page_title FROM {$this->t( 'occurrences' )} o LEFT JOIN {$this->t( 'run_urls' )} u ON u.id = o.run_url_id WHERE o.id = %d", (int) $id ), ARRAY_A );
		return $row ? $row : null;
	}

	/**
	 * Link a run's occurrences to their issue.
	 *
	 * @param int    $run_id    Run ID.
	 * @param string $issue_key Key.
	 * @param int    $issue_id  Issue ID.
	 */
	public function link_occurrences( $run_id, $issue_key, $issue_id ) {
		global $wpdb;
		$wpdb->query( $wpdb->prepare( "UPDATE {$this->t( 'occurrences' )} SET issue_id = %d WHERE run_id = %d AND issue_key = %s", (int) $issue_id, (int) $run_id, $issue_key ) );
	}

	/**
	 * Count of occurrences in a run by severity.
	 *
	 * @param int $run_id Run ID.
	 * @return array severity => count
	 */
	public function severity_counts( $run_id ) {
		global $wpdb;
		$rows = (array) $wpdb->get_results( $wpdb->prepare( "SELECT severity, COUNT(*) AS n FROM {$this->t( 'occurrences' )} WHERE run_id = %d GROUP BY severity", (int) $run_id ), ARRAY_A );
		$out  = array();
		foreach ( $rows as $row ) {
			$out[ $row['severity'] ] = (int) $row['n'];
		}
		return $out;
	}

	/**
	 * Occurrences of a run for the findings screen and export, joined to the
	 * page and the issue.
	 *
	 * @param int   $run_id Run ID.
	 * @param array $filter { severity, rule_id, work_status, display, search, issue_ids }.
	 * @param int   $limit  Limit (0 for all).
	 * @param int   $offset Offset.
	 * @return array
	 */
	public function findings( $run_id, array $filter = array(), $limit = 50, $offset = 0 ) {
		global $wpdb;
		list( $where, $args ) = $this->finding_where( $run_id, $filter );
		$sql                  = "SELECT o.*, u.url AS page_url, u.title AS page_title, i.id AS issue_id, i.work_status, i.owner_user_id, i.due_date, i.first_observed_utc, i.last_observed_utc, i.verification_state, i.verification_run_id, i.external_link
			FROM {$this->t( 'occurrences' )} o
			LEFT JOIN {$this->t( 'run_urls' )} u ON u.id = o.run_url_id
			LEFT JOIN {$this->t( 'issues' )} i ON i.issue_key = o.issue_key
			WHERE $where ORDER BY o.id ASC";
		if ( $limit > 0 ) {
			$sql   .= ' LIMIT %d OFFSET %d';
			$args[] = (int) $limit;
			$args[] = (int) $offset;
		}
		return (array) $wpdb->get_results( $wpdb->prepare( $sql, $args ), ARRAY_A ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- Built from fixed clauses with placeholders.
	}

	/**
	 * Number of findings matching a filter.
	 *
	 * @param int   $run_id Run ID.
	 * @param array $filter Filter.
	 * @return int
	 */
	public function count_findings( $run_id, array $filter = array() ) {
		global $wpdb;
		list( $where, $args ) = $this->finding_where( $run_id, $filter );
		$sql                  = "SELECT COUNT(*) FROM {$this->t( 'occurrences' )} o
			LEFT JOIN {$this->t( 'run_urls' )} u ON u.id = o.run_url_id
			LEFT JOIN {$this->t( 'issues' )} i ON i.issue_key = o.issue_key
			WHERE $where";
		return (int) $wpdb->get_var( $wpdb->prepare( $sql, $args ) ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- Built from fixed clauses with placeholders.
	}

	/**
	 * WHERE clause for findings: fixed fragments with placeholders only.
	 *
	 * @param int   $run_id Run ID.
	 * @param array $filter Filter.
	 * @return array [ sql, args ]
	 */
	private function finding_where( $run_id, array $filter ) {
		global $wpdb;
		$where = array( 'o.run_id = %d' );
		$args  = array( (int) $run_id );
		$map   = array(
			'severity'    => 'o.severity = %s',
			'rule_id'     => 'o.rule_id = %s',
			'outcome'     => 'o.outcome = %s',
			'work_status' => 'i.work_status = %s',
		);
		foreach ( $map as $key => $clause ) {
			if ( ! empty( $filter[ $key ] ) ) {
				$where[] = $clause;
				$args[]  = (string) $filter[ $key ];
			}
		}
		if ( ! empty( $filter['rule_ids'] ) ) {
			$where[] = 'o.rule_id IN (' . implode( ',', array_fill( 0, count( $filter['rule_ids'] ), '%s' ) ) . ')';
			$args    = array_merge( $args, array_values( $filter['rule_ids'] ) );
		}
		if ( isset( $filter['search'] ) && '' !== (string) $filter['search'] ) {
			$where[] = '(u.url LIKE %s OR u.title LIKE %s OR o.observed LIKE %s)';
			$like    = '%' . $wpdb->esc_like( (string) $filter['search'] ) . '%';
			$args[]  = $like;
			$args[]  = $like;
			$args[]  = $like;
		}
		return array( implode( ' AND ', $where ), $args );
	}

	/* ---------------------------------------------------------------- Issues */

	/**
	 * Every issue, keyed by issue key.
	 *
	 * @return array
	 */
	public function issues_by_key() {
		global $wpdb;
		$rows = (array) $wpdb->get_results( "SELECT * FROM {$this->t( 'issues' )}", ARRAY_A );
		$out  = array();
		foreach ( $rows as $row ) {
			$out[ $row['issue_key'] ] = $row;
		}
		return $out;
	}

	/**
	 * One issue.
	 *
	 * @param int $id Issue ID.
	 * @return array|null
	 */
	public function get_issue( $id ) {
		global $wpdb;
		$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$this->t( 'issues' )} WHERE id = %d", (int) $id ), ARRAY_A );
		return $row ? $row : null;
	}

	/**
	 * Insert an issue.
	 *
	 * @param array $fields Fields.
	 * @return int
	 */
	public function insert_issue( array $fields ) {
		global $wpdb;
		$fields = array_merge(
			array(
				'exception_reason' => '',
				'evidence'         => '',
			),
			$fields
		);
		$wpdb->insert( $this->t( 'issues' ), $fields );
		return (int) $wpdb->insert_id;
	}

	/**
	 * Update an issue.
	 *
	 * @param int   $id     Issue ID.
	 * @param array $fields Fields.
	 */
	public function update_issue( $id, array $fields ) {
		global $wpdb;
		$fields['updated_utc'] = self::now();
		$wpdb->update( $this->t( 'issues' ), $fields, array( 'id' => (int) $id ) );
	}

	/**
	 * Issues by ID.
	 *
	 * @param array $ids IDs.
	 * @return array
	 */
	public function issues_by_ids( array $ids ) {
		global $wpdb;
		$ids = array_values( array_filter( array_map( 'intval', $ids ) ) );
		if ( empty( $ids ) ) {
			return array();
		}
		$in = implode( ',', array_fill( 0, count( $ids ), '%d' ) );
		return (array) $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$this->t( 'issues' )} WHERE id IN ($in)", $ids ), ARRAY_A ); // phpcs:ignore WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare -- $in is a list of %d placeholders.
	}

	/**
	 * The issue register across runs: current issue state with the latest evidence.
	 *
	 * @param array $filter { work_status, verification_state, owner (user ID, or -1 for nobody), search }.
	 * @param int   $limit  Limit (0 for all).
	 * @param int   $offset Offset.
	 * @return array
	 */
	public function register( array $filter = array(), $limit = 50, $offset = 0 ) {
		global $wpdb;
		list( $where, $args ) = $this->register_where( $filter );
		$sql                  = "SELECT i.*, o.observed AS latest_observed FROM {$this->t( 'issues' )} i
			LEFT JOIN {$this->t( 'occurrences' )} o ON o.id = i.latest_occurrence_id
			WHERE $where ORDER BY i.last_observed_utc DESC, i.id DESC";
		if ( $limit > 0 ) {
			$sql   .= ' LIMIT %d OFFSET %d';
			$args[] = (int) $limit;
			$args[] = (int) $offset;
		}
		return (array) $wpdb->get_results( $wpdb->prepare( $sql, $args ), ARRAY_A ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- Built from fixed clauses with placeholders.
	}

	/**
	 * Number of issues matching a register filter.
	 *
	 * @param array $filter Filter.
	 * @return int
	 */
	public function count_register( array $filter = array() ) {
		global $wpdb;
		list( $where, $args ) = $this->register_where( $filter );
		return (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$this->t( 'issues' )} i WHERE $where", $args ) ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare -- Built from fixed clauses with placeholders.
	}

	/**
	 * Owners that hold at least one issue, for the register's owner filter.
	 *
	 * @return array User IDs.
	 */
	public function register_owner_ids() {
		global $wpdb;
		return array_map( 'intval', (array) $wpdb->get_col( "SELECT DISTINCT owner_user_id FROM {$this->t( 'issues' )} WHERE owner_user_id > 0 ORDER BY owner_user_id" ) );
	}

	/**
	 * WHERE clause for the register: fixed fragments with placeholders only.
	 *
	 * @param array $filter Filter.
	 * @return array [ sql, args ]
	 */
	private function register_where( array $filter ) {
		global $wpdb;
		$where = array( 'i.id > %d' ); // Always a placeholder, so prepare() is happy with no filter.
		$args  = array( 0 );
		$map   = array(
			'work_status'        => 'i.work_status = %s',
			'verification_state' => 'i.verification_state = %s',
		);
		foreach ( $map as $key => $clause ) {
			if ( ! empty( $filter[ $key ] ) ) {
				$where[] = $clause;
				$args[]  = (string) $filter[ $key ];
			}
		}
		if ( isset( $filter['owner'] ) && '' !== (string) $filter['owner'] ) {
			$owner = (int) $filter['owner'];
			if ( $owner < 0 ) {
				$where[] = 'i.owner_user_id = 0';
			} elseif ( $owner > 0 ) {
				$where[] = 'i.owner_user_id = %d';
				$args[]  = $owner;
			}
		}
		if ( isset( $filter['search'] ) && '' !== (string) $filter['search'] ) {
			$where[] = '(i.page_url LIKE %s OR i.rule_id LIKE %s OR i.entity_key LIKE %s)';
			$like    = '%' . $wpdb->esc_like( (string) $filter['search'] ) . '%';
			$args[]  = $like;
			$args[]  = $like;
			$args[]  = $like;
		}
		return array( implode( ' AND ', $where ), $args );
	}

	/**
	 * Issue counts by work status and verification state.
	 *
	 * @return array { work: status => n, verification: state => n }
	 */
	public function issue_counts() {
		global $wpdb;
		$out = array(
			'work'         => array(),
			'verification' => array(),
		);
		foreach ( (array) $wpdb->get_results( "SELECT work_status, COUNT(*) AS n FROM {$this->t( 'issues' )} GROUP BY work_status", ARRAY_A ) as $row ) {
			$out['work'][ $row['work_status'] ] = (int) $row['n'];
		}
		foreach ( (array) $wpdb->get_results( "SELECT verification_state, COUNT(*) AS n FROM {$this->t( 'issues' )} GROUP BY verification_state", ARRAY_A ) as $row ) {
			$out['verification'][ $row['verification_state'] ] = (int) $row['n'];
		}
		return $out;
	}

	/* ---------------------------------------------------------------- Events */

	/**
	 * Append to the event log. Data must hold IDs, counts and codes only (D2).
	 *
	 * @param string $type        Event type.
	 * @param array  $data        Data.
	 * @param int    $user_id     Acting user, 0 for the system.
	 * @param string $object_type Object type.
	 * @param int    $object_id   Object ID.
	 * @param int    $run_id      Run ID.
	 */
	public function log_event( $type, array $data = array(), $user_id = 0, $object_type = '', $object_id = 0, $run_id = 0 ) {
		global $wpdb;
		$wpdb->insert(
			$this->t( 'events' ),
			array(
				'created_utc'   => self::now(),
				'actor_type'    => $user_id ? 'user' : 'system',
				'actor_user_id' => (int) $user_id,
				'event_type'    => substr( (string) $type, 0, 40 ),
				'object_type'   => (string) $object_type,
				'object_id'     => (int) $object_id,
				'run_id'        => (int) $run_id,
				'data'          => (string) wp_json_encode( $data ),
			)
		);
	}

	/**
	 * Events for an object.
	 *
	 * @param string $object_type Type.
	 * @param int    $object_id   ID.
	 * @return array
	 */
	public function events_for( $object_type, $object_id ) {
		global $wpdb;
		return (array) $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$this->t( 'events' )} WHERE object_type = %s AND object_id = %d ORDER BY id ASC", $object_type, (int) $object_id ), ARRAY_A );
	}

	/**
	 * The latest event of one type on each of several objects, in as few queries as possible.
	 *
	 * Large sets are read in chunks so one statement never carries thousands of placeholders.
	 *
	 * @param string $object_type Type.
	 * @param string $event_type  Event type.
	 * @param array  $object_ids  IDs.
	 * @return array object_id => event row (object_id, data)
	 */
	public function latest_events_for( $object_type, $event_type, array $object_ids ) {
		global $wpdb;
		$out = array();
		$ids = array_values( array_unique( array_map( 'intval', $object_ids ) ) );
		foreach ( array_chunk( $ids, 500 ) as $chunk ) {
			$in   = implode( ',', array_fill( 0, count( $chunk ), '%d' ) );
			$args = array_merge( array( (string) $object_type, (string) $event_type ), $chunk );
			$rows = (array) $wpdb->get_results(
				$wpdb->prepare( "SELECT e.object_id, e.data FROM {$this->t( 'events' )} e INNER JOIN ( SELECT MAX(id) AS last_id FROM {$this->t( 'events' )} WHERE object_type = %s AND event_type = %s AND object_id IN ($in) GROUP BY object_id ) l ON e.id = l.last_id", $args ), // phpcs:ignore WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare,WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber,WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- $in is a list of %d placeholders.
				ARRAY_A
			);
			foreach ( $rows as $row ) {
				$out[ (int) $row['object_id'] ] = $row;
			}
		}
		return $out;
	}

	/**
	 * Recent events, optionally of some types.
	 *
	 * @param int   $limit Limit.
	 * @param array $types Event types.
	 * @return array
	 */
	public function recent_events( $limit = 50, array $types = array() ) {
		global $wpdb;
		if ( empty( $types ) ) {
			return (array) $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$this->t( 'events' )} ORDER BY id DESC LIMIT %d", (int) $limit ), ARRAY_A );
		}
		$in   = implode( ',', array_fill( 0, count( $types ), '%s' ) );
		$args = array_merge( array_values( $types ), array( (int) $limit ) );
		return (array) $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$this->t( 'events' )} WHERE event_type IN ($in) ORDER BY id DESC LIMIT %d", $args ), ARRAY_A ); // phpcs:ignore WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare -- $in is a list of %s placeholders.
	}

	/**
	 * Events in a run with an issue object (change log).
	 *
	 * @param int $from_id Events after this ID.
	 * @param int $limit   Limit.
	 * @return array
	 */
	public function issue_events_since( $from_id, $limit = 5000 ) {
		global $wpdb;
		return (array) $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$this->t( 'events' )} WHERE object_type = 'issue' AND id > %d ORDER BY id ASC LIMIT %d", (int) $from_id, (int) $limit ), ARRAY_A );
	}

	/**
	 * Change log for a run: register events the run recorded, and staff
	 * changes and notes on the issues the run found, with rule and page.
	 *
	 * @param int $run_id Run ID.
	 * @return array
	 */
	public function run_issue_events( $run_id ) {
		global $wpdb;
		return (array) $wpdb->get_results( $wpdb->prepare( "SELECT e.*, i.rule_id, i.page_url FROM {$this->t( 'events' )} e JOIN {$this->t( 'issues' )} i ON i.id = e.object_id WHERE e.object_type = 'issue' AND ( e.run_id = %d OR e.object_id IN ( SELECT DISTINCT issue_id FROM {$this->t( 'occurrences' )} WHERE run_id = %d ) ) ORDER BY e.id ASC", (int) $run_id, (int) $run_id ), ARRAY_A );
	}

	/* ---------------------------------------------------------------- Outbox */

	/**
	 * Add an outbox row; an existing row for the same run, type and
	 * recipient is left as it is (unique index).
	 *
	 * @param array $fields Fields.
	 * @return int 0 if it already existed.
	 */
	public function insert_outbox( array $fields ) {
		global $wpdb;
		$exists = $wpdb->get_var( $wpdb->prepare( "SELECT id FROM {$this->t( 'outbox' )} WHERE run_id = %d AND notification_type = %s AND recipient = %s", (int) $fields['run_id'], $fields['notification_type'], $fields['recipient'] ) );
		if ( $exists ) {
			return 0;
		}
		$fields   = array_merge( array( 'created_utc' => self::now() ), $fields );
		$suppress = $wpdb->suppress_errors( true );
		$ok       = $wpdb->insert( $this->t( 'outbox' ), $fields );
		$wpdb->suppress_errors( $suppress );
		return $ok ? (int) $wpdb->insert_id : 0;
	}

	/**
	 * Outbox rows in some states.
	 *
	 * @param array $states States.
	 * @param int   $limit  Limit.
	 * @return array
	 */
	public function outbox_in( array $states, $limit = 100 ) {
		global $wpdb;
		$in   = implode( ',', array_fill( 0, count( $states ), '%s' ) );
		$args = array_merge( array_values( $states ), array( (int) $limit ) );
		return (array) $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$this->t( 'outbox' )} WHERE state IN ($in) ORDER BY id ASC LIMIT %d", $args ), ARRAY_A ); // phpcs:ignore WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare -- $in is a list of %s placeholders.
	}

	/**
	 * Pending outbox rows that are due now, earliest first, so rows waiting
	 * for a retry never crowd due rows out of the limit (finding 5).
	 *
	 * @param int $now   Unix time.
	 * @param int $limit Limit.
	 * @return array
	 */
	public function outbox_due( $now, $limit = 20 ) {
		global $wpdb;
		return (array) $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$this->t( 'outbox' )} WHERE state = 'pending' AND not_before <= %d ORDER BY not_before ASC, id ASC LIMIT %d", (int) $now, (int) $limit ), ARRAY_A );
	}

	/**
	 * When the outbox next has work: the earliest pending not_before, or the
	 * moment the earliest sending claim expires (so an interrupted send is
	 * marked delivery_unknown). Null when there is nothing to do.
	 *
	 * @return int|null Unix time.
	 */
	public function outbox_next_due() {
		global $wpdb;
		$next = $wpdb->get_var( "SELECT MIN(t) FROM ( SELECT MIN(not_before) AS t FROM {$this->t( 'outbox' )} WHERE state = 'pending' UNION ALL SELECT MIN(claimed_until) + 1 AS t FROM {$this->t( 'outbox' )} WHERE state = 'sending' ) AS due" );
		return null === $next ? null : (int) $next;
	}

	/**
	 * Atomically claim one pending outbox row (M6): pending to sending, with
	 * a token, only if nobody else holds it.
	 *
	 * @param int    $id    Row ID.
	 * @param string $token Token.
	 * @param int    $ttl   Seconds.
	 * @return bool
	 */
	public function claim_outbox( $id, $token, $ttl ) {
		global $wpdb;
		$now      = time();
		$affected = $wpdb->query( $wpdb->prepare( "UPDATE {$this->t( 'outbox' )} SET state = 'sending', claim_token = %s, claimed_until = %d, attempts = attempts + 1, updated_utc = %s WHERE id = %d AND state = 'pending' AND not_before <= %d", $token, $now + (int) $ttl, self::now(), (int) $id, $now ) );
		if ( ! $affected ) {
			return false;
		}
		return $token === $wpdb->get_var( $wpdb->prepare( "SELECT claim_token FROM {$this->t( 'outbox' )} WHERE id = %d AND state = 'sending'", (int) $id ) );
	}

	/**
	 * Update an outbox row, only while this token holds it when one is given.
	 *
	 * @param int    $id     Row ID.
	 * @param array  $fields Fields.
	 * @param string $token  Claim token or ''.
	 */
	public function update_outbox( $id, array $fields, $token = '' ) {
		global $wpdb;
		$fields['updated_utc'] = self::now();
		$where                 = array( 'id' => (int) $id );
		if ( '' !== $token ) {
			$where['claim_token'] = $token;
		}
		$wpdb->update( $this->t( 'outbox' ), $fields, $where );
	}

	/**
	 * Outbox counts by state.
	 *
	 * @return array
	 */
	public function outbox_counts() {
		global $wpdb;
		$out = array();
		foreach ( (array) $wpdb->get_results( "SELECT state, COUNT(*) AS n FROM {$this->t( 'outbox' )} GROUP BY state", ARRAY_A ) as $row ) {
			$out[ $row['state'] ] = (int) $row['n'];
		}
		return $out;
	}

	/**
	 * Recent outbox rows.
	 *
	 * @param int $limit Limit.
	 * @return array
	 */
	public function recent_outbox( $limit = 20 ) {
		global $wpdb;
		return (array) $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$this->t( 'outbox' )} ORDER BY id DESC LIMIT %d", (int) $limit ), ARRAY_A );
	}

	/* ------------------------------------------------------------- Retention */

	/**
	 * Run IDs that hold the latest evidence for an issue still in play.
	 *
	 * @return array
	 */
	public function evidence_run_ids() {
		global $wpdb;
		$ids = $wpdb->get_col( "SELECT DISTINCT o.run_id FROM {$this->t( 'issues' )} i JOIN {$this->t( 'occurrences' )} o ON o.id = i.latest_occurrence_id WHERE i.work_status NOT IN ('resolved','false_positive')" );
		return array_map( 'intval', (array) $ids );
	}

	/**
	 * Finished runs, newest first.
	 *
	 * @return array
	 */
	public function finished_runs() {
		global $wpdb;
		return (array) $wpdb->get_results( "SELECT id, run_type, state, finished_utc FROM {$this->t( 'runs' )} WHERE state NOT IN ('queued','running') ORDER BY id DESC", ARRAY_A );
	}

	/**
	 * Delete a run's page observations, blocks and occurrences, keeping the
	 * run row itself as a record that it happened.
	 *
	 * @param int $run_id Run ID.
	 */
	public function purge_run_evidence( $run_id ) {
		global $wpdb;
		foreach ( array( 'blocks', 'occurrences', 'run_urls' ) as $table ) {
			$wpdb->query( $wpdb->prepare( "DELETE FROM {$this->t( $table )} WHERE run_id = %d", (int) $run_id ) );
		}
		$this->update_run( $run_id, array( 'state' => 'purged' ) );
	}
}
