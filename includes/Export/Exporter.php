<?php
/**
 * Builds the export for one frozen run (contract section 7): Summary,
 * Pages, Findings and Change log as UTF-8 CSV, plus manifest.json, as a ZIP
 * or as one CSV on its own. Streamed to the browser; nothing touches disk.
 *
 * @package MLT\SchemaAudit
 */

namespace MLT\SchemaAudit\Export;

use MLT\SchemaAudit\Engine\Rules;
use MLT\SchemaAudit\Issues;
use MLT\SchemaAudit\Labels;
use MLT\SchemaAudit\Store\Repository;

defined( 'ABSPATH' ) || exit;

/**
 * Exporter.
 */
class Exporter {

	/**
	 * Files in the ZIP.
	 */
	const FILES = array( 'summary', 'pages', 'findings', 'changelog' );

	/**
	 * Finding columns, in the contract's order.
	 */
	const FINDING_COLUMNS = array( 'Finding ID', 'Run ID', 'Page URL', 'Page title', 'Entity ID', 'Entity type', 'Rule ID', 'Rule version', 'Rule title', 'Category', 'Display group', 'Outcome', 'Severity', 'Confidence', 'Source attribution', 'Source confidence', 'Block', 'JSON path', 'Observed value', 'Comparison value', 'Evidence snippet', 'Explanation', 'Suggested investigation', 'First observed (UTC)', 'Last observed (UTC)', 'Work status', 'Verification state', 'Owner', 'Due date', 'Note', 'Verification run' );

	/**
	 * Repository.
	 *
	 * @var Repository
	 */
	private $repo;

	/**
	 * Run.
	 *
	 * @var array
	 */
	private $run;

	/**
	 * Filter applied to findings.
	 *
	 * @var array
	 */
	private $filter;

	/**
	 * Constructor.
	 *
	 * @param array $run    Run row.
	 * @param array $filter Findings filter (empty for a full export).
	 */
	public function __construct( array $run, array $filter = array() ) {
		$this->repo   = new Repository();
		$this->run    = $run;
		$this->filter = array_filter( $filter, 'strlen' );
	}

	/**
	 * Base file name.
	 *
	 * @return string
	 */
	public function basename() {
		$host = preg_replace( '/[^a-z0-9.\-]/i', '', (string) wp_parse_url( home_url( '/' ), PHP_URL_HOST ) );
		return sprintf( 'schema-audit-%s-run-%d-%s', $host, (int) $this->run['id'], gmdate( 'Ymd', strtotime( $this->run['created_utc'] . ' UTC' ) ) );
	}

	/**
	 * Every file of the export.
	 *
	 * @return array name => contents
	 */
	public function files() {
		$out = array();
		foreach ( self::FILES as $file ) {
			$out[ $file . '.csv' ] = $this->csv( $file );
		}
		$out['manifest.json'] = (string) wp_json_encode( $this->manifest(), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE );
		return $out;
	}

	/**
	 * Manifest.
	 *
	 * @return array
	 */
	public function manifest() {
		$scope = Repository::decode( $this->run['scope'] );
		return array(
			'tool'             => 'MLT Schema Audit',
			'plugin_version'   => MLTSA_VERSION,
			'coverage'         => Labels::COVERAGE_STATEMENT,
			'site'             => home_url( '/' ),
			'run_id'           => (int) $this->run['id'],
			'run_type'         => $this->run['run_type'],
			'run_state'        => $this->run['state'],
			'complete'         => 'complete' === $this->run['state'],
			'created_utc'      => $this->run['created_utc'],
			'started_utc'      => $this->run['started_utc'],
			'finished_utc'     => $this->run['finished_utc'],
			'engine_version'   => $this->run['engine_version'],
			'ruleset_version'  => $this->run['ruleset_version'],
			'baseline_run_id'  => (int) $this->run['baseline_run_id'],
			'scope'            => $scope,
			'exported_utc'     => Repository::now(),
			'export'           => empty( $this->filter ) ? 'full' : 'filtered',
			'filter'           => (object) $this->filter,
			'files'            => array_map(
				static function ( $f ) {
					return $f . '.csv';
				},
				self::FILES
			),
		);
	}

	/**
	 * One CSV.
	 *
	 * @param string $file summary, pages, findings or changelog.
	 * @return string
	 */
	public function csv( $file ) {
		switch ( $file ) {
			case 'summary':
				return $this->summary();
			case 'pages':
				return $this->pages();
			case 'findings':
				return $this->findings();
			case 'changelog':
				return $this->changelog();
		}
		return '';
	}

	/**
	 * Summary sheet: one key-value row each.
	 *
	 * @return string
	 */
	private function summary() {
		$summary  = Repository::decode( $this->run['summary'] );
		$rows     = array(
			array( 'Coverage', Labels::COVERAGE_STATEMENT ),
			array( 'Site', home_url( '/' ) ),
			array( 'Run ID', (int) $this->run['id'] ),
			array( 'Run type', $this->run['run_type'] ),
			array( 'Run state', Labels::of( Labels::RUN_STATES, $this->run['state'] ) ),
			array( 'Started (UTC)', $this->run['started_utc'] ),
			array( 'Finished (UTC)', $this->run['finished_utc'] ),
			array( 'Engine version', $this->run['engine_version'] ),
			array( 'Rule set version', $this->run['ruleset_version'] ),
			array( 'Baseline run ID', (int) $this->run['baseline_run_id'] ),
			array( 'Export', empty( $this->filter ) ? 'Full' : 'Filtered: ' . (string) wp_json_encode( $this->filter ) ),
			array( 'Pages in scope', (int) $this->run['url_count'] ),
			array( 'Pages excluded', (int) $this->run['excluded_count'] ),
		);
		foreach ( isset( $summary['coverage'] ) ? (array) $summary['coverage'] : array() as $state => $n ) {
			$rows[] = array( 'Pages: ' . Labels::of( Labels::COVERAGE, $state ), (int) $n );
		}
		foreach ( isset( $summary['severity'] ) ? (array) $summary['severity'] : array() as $severity => $n ) {
			$rows[] = array( 'Findings: ' . Labels::of( Labels::SEVERITIES, $severity ), (int) $n );
		}
		foreach ( isset( $summary['comparison'] ) ? (array) $summary['comparison'] : array() as $key => $n ) {
			if ( is_int( $n ) ) {
				$rows[] = array( 'Compared with baseline: ' . str_replace( '_', ' ', $key ), $n );
			}
		}
		return Csv::document( array( 'Item', 'Value' ), $rows );
	}

	/**
	 * Pages sheet.
	 *
	 * @return string
	 */
	private function pages() {
		$rows   = array();
		$offset = 0;
		do {
			$batch = $this->repo->run_urls( (int) $this->run['id'], 500, $offset );
			foreach ( $batch as $u ) {
				$rows[] = array( $u['url'], $u['title'], $u['discovery_source'], (int) $u['post_id'], Labels::of( Labels::COVERAGE, $u['coverage'] ), $u['coverage_reason'], (int) $u['http_status'], $u['final_url'], $u['canonical'], $u['robots'], (int) $u['jsonld_count'], (int) $u['microdata'], (int) $u['rdfa'], $u['fetched_utc'], (int) $u['duration_ms'], $u['markup_hash'] );
			}
			$offset += 500;
		} while ( count( $batch ) === 500 );
		return Csv::document( array( 'Page URL', 'Page title', 'Discovery source', 'Post ID', 'Coverage', 'Coverage reason', 'HTTP status', 'Final URL', 'Canonical', 'Robots', 'JSON-LD blocks', 'Microdata items', 'RDFa attributes', 'Fetched (UTC)', 'Response time (ms)', 'Markup hash' ), $rows );
	}

	/**
	 * Findings sheet.
	 *
	 * @return string
	 */
	private function findings() {
		$filter = $this->filter;
		if ( ! empty( $filter['display'] ) ) {
			$filter['rule_ids'] = self::rules_in_display( $filter['display'] );
		}
		$findings = $this->repo->findings( (int) $this->run['id'], $filter, 0 );
		$notes    = Issues::latest_notes( array_filter( array_column( $findings, 'issue_id' ) ) );
		$catalog  = Rules::catalogue();
		$rows     = array();
		foreach ( $findings as $f ) {
			$rule   = isset( $catalog[ $f['rule_id'] ] ) ? $catalog[ $f['rule_id'] ] : null;
			$owner  = (int) $f['owner_user_id'] ? get_userdata( (int) $f['owner_user_id'] ) : false;
			$rows[] = array(
				(int) $f['id'],
				(int) $f['run_id'],
				$f['site_wide'] && '' === (string) $f['page_url'] ? '(site-wide)' : $f['page_url'],
				$f['page_title'],
				$f['entity_key'],
				$f['entity_type'],
				$f['rule_id'],
				(int) $f['rule_version'],
				$rule ? $rule['title'] : '',
				$rule ? Rules::GROUPS[ $rule['group'] ] : '',
				$rule ? Rules::DISPLAY[ $rule['display'] ] : '',
				Labels::of( Labels::OUTCOMES, $f['outcome'] ),
				Labels::of( Labels::SEVERITIES, $f['severity'] ),
				$f['confidence'],
				$f['source'],
				$f['source_confidence'],
				(int) $f['block_index'] >= 0 ? (int) $f['block_index'] + 1 : '',
				$f['json_path'],
				$f['observed'],
				$f['comparison'],
				$f['snippet'],
				$rule ? $rule['explanation'] : '',
				$rule ? $rule['investigate'] : '',
				$f['first_observed_utc'],
				$f['last_observed_utc'],
				Labels::of( Labels::WORK, (string) $f['work_status'] ),
				Labels::of( Labels::VERIFICATION, (string) $f['verification_state'] ),
				$owner ? $owner->display_name : '',
				$f['due_date'],
				isset( $notes[ (int) $f['issue_id'] ] ) ? $notes[ (int) $f['issue_id'] ] : '',
				(int) $f['verification_run_id'] ? (int) $f['verification_run_id'] : '',
			);
		}
		return Csv::document( self::FINDING_COLUMNS, $rows );
	}

	/**
	 * Change log: register events recorded by this run, then staff changes
	 * to the issues this run found.
	 *
	 * @return string
	 */
	private function changelog() {
		$rows = array();
		foreach ( $this->repo->run_issue_events( (int) $this->run['id'] ) as $e ) {
			$data   = Repository::decode( $e['data'] );
			$actor  = (int) $e['actor_user_id'] ? get_userdata( (int) $e['actor_user_id'] ) : false;
			$detail = 'note' === $e['event_type'] ? ( isset( $data['text'] ) ? $data['text'] : '' ) : (string) wp_json_encode( $data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE );
			$rows[] = array( $e['created_utc'], (int) $e['object_id'], $e['rule_id'], $e['page_url'], $e['event_type'], $detail, $actor ? $actor->display_name : 'System', (int) $e['run_id'] ? (int) $e['run_id'] : '' );
		}
		return Csv::document( array( 'Time (UTC)', 'Issue ID', 'Rule ID', 'Page URL', 'Event', 'Detail', 'By', 'Run ID' ), $rows );
	}

	/**
	 * Rule IDs in a display group.
	 *
	 * @param string $display Display group key.
	 * @return array
	 */
	public static function rules_in_display( $display ) {
		$out = array();
		foreach ( Rules::catalogue() as $id => $rule ) {
			if ( $rule['display'] === $display ) {
				$out[] = $id;
			}
		}
		return $out;
	}

	/**
	 * Stream the ZIP.
	 */
	public function send_zip() {
		$this->headers( 'application/zip', $this->basename() . '.zip' );
		$zip = new ZipStream(
			static function ( $bytes ) {
				echo $bytes; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Binary ZIP stream.
			},
			time()
		);
		foreach ( $this->files() as $name => $contents ) {
			$zip->add( $name, $contents );
		}
		$zip->finish();
	}

	/**
	 * Stream one CSV.
	 *
	 * @param string $file File key.
	 */
	public function send_csv( $file ) {
		$this->headers( 'text/csv; charset=UTF-8', $this->basename() . '-' . $file . '.csv' );
		echo $this->csv( $file ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- CSV body, cells neutralised by Csv::cell().
	}

	/**
	 * Download headers.
	 *
	 * @param string $type     Content type.
	 * @param string $filename File name.
	 */
	private function headers( $type, $filename ) {
		nocache_headers();
		header( 'Content-Type: ' . $type );
		header( 'Content-Disposition: attachment; filename="' . preg_replace( '/[^A-Za-z0-9._\-]/', '', $filename ) . '"' );
		header( 'X-Content-Type-Options: nosniff' );
	}
}
