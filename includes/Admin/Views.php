<?php
/**
 * Admin screens: Audits, Findings, Settings and Health.
 *
 * Everything shown is escaped on output (A1). Evidence and fetched values
 * are plain text. Each screen checks its capability again, so a direct
 * request cannot skip the menu's check (A2).
 *
 * @package MLT\SchemaAudit
 */

namespace MLT\SchemaAudit\Admin;

use MLT\SchemaAudit\Engine\Rules;
use MLT\SchemaAudit\Export\Exporter;
use MLT\SchemaAudit\Labels;
use MLT\SchemaAudit\Ops\Scheduler;
use MLT\SchemaAudit\Settings;
use MLT\SchemaAudit\Store\Repository;

defined( 'ABSPATH' ) || exit;

/**
 * Views.
 */
class Views {

	/**
	 * Rows per page in tables.
	 */
	const PER_PAGE = 50;

	/**
	 * Stop unless the user holds a capability.
	 *
	 * @param string $cap Capability.
	 */
	private static function require_cap( $cap ) {
		if ( ! current_user_can( $cap ) ) {
			wp_die( esc_html__( 'You do not have permission to view this page.', 'mlt-schema-audit' ), '', array( 'response' => 403 ) );
		}
	}

	/**
	 * Admin URL for one of the plugin's pages.
	 *
	 * @param string $page Slug.
	 * @param array  $args Query args.
	 * @return string
	 */
	public static function url( $page, array $args = array() ) {
		return add_query_arg( array_merge( array( 'page' => $page ), $args ), admin_url( 'admin.php' ) );
	}

	/**
	 * An integer query argument.
	 *
	 * @param string $key Key.
	 * @return int
	 */
	private static function arg_int( $key ) {
		return isset( $_GET[ $key ] ) ? absint( wp_unslash( $_GET[ $key ] ) ) : 0; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only screen state.
	}

	/**
	 * A key-like query argument.
	 *
	 * @param string $key Key.
	 * @return string
	 */
	private static function arg_key( $key ) {
		return isset( $_GET[ $key ] ) ? sanitize_key( wp_unslash( $_GET[ $key ] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only screen state.
	}

	/**
	 * Screen header, notices and the coverage statement.
	 *
	 * @param string $title Title.
	 */
	private static function open( $title ) {
		echo '<div class="wrap mltsa"><h1>' . esc_html( $title ) . '</h1>';
		$code = self::arg_key( 'mltsa_notice' );
		if ( isset( Admin::NOTICES[ $code ] ) ) {
			list( $type, $message ) = Admin::NOTICES[ $code ];
			echo '<div class="notice notice-' . esc_attr( $type ) . '"><p>' . esc_html( $message ) . '</p></div>';
		}
		foreach ( Admin::take_errors() as $error ) {
			echo '<div class="notice notice-error"><p>' . esc_html( $error ) . '</p></div>';
		}
		if ( Settings::constant_disabled() ) {
			echo '<div class="notice notice-warning"><p>' . esc_html__( 'MLTSA_DISABLE is set: scheduling, mail and manual audits are stopped.', 'mlt-schema-audit' ) . '</p></div>';
		}
		echo '<p class="mltsa-coverage">' . esc_html( Labels::COVERAGE_STATEMENT ) . '</p>';
	}

	/**
	 * Close the screen.
	 */
	private static function close() {
		echo '</div>';
	}

	/**
	 * Local time for a UTC database value.
	 *
	 * @param string|null $utc Y-m-d H:i:s.
	 * @return string
	 */
	private static function when( $utc ) {
		return $utc ? wp_date( 'j M Y, H:i', strtotime( $utc . ' UTC' ) ) : '';
	}

	/**
	 * A form that posts to admin-post.php with a nonce.
	 *
	 * @param string $action Action.
	 * @param string $label  Button label.
	 * @param array  $hidden Hidden fields.
	 * @param string $button_class Button class.
	 */
	private static function button_form( $action, $label, array $hidden = array(), $button_class = 'button button-primary' ) {
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" class="mltsa-inline">';
		echo '<input type="hidden" name="action" value="' . esc_attr( $action ) . '">';
		foreach ( $hidden as $name => $value ) {
			echo '<input type="hidden" name="' . esc_attr( $name ) . '" value="' . esc_attr( $value ) . '">';
		}
		wp_nonce_field( $action );
		echo '<button type="submit" class="' . esc_attr( $button_class ) . '">' . esc_html( $label ) . '</button></form>';
	}

	/* ---------------------------------------------------------------- Audits */

	/**
	 * Audits screen, or one audit.
	 */
	public static function audits() {
		self::require_cap( 'mltsa_audit' );
		$run_id = self::arg_int( 'run' );
		if ( $run_id ) {
			self::run_detail( $run_id );
			return;
		}
		$repo = new Repository();
		self::open( __( 'Schema Audit', 'mlt-schema-audit' ) );
		$active = $repo->active_run();
		if ( $active ) {
			self::progress( $active );
		} else {
			echo '<p>' . esc_html__( 'Run a manual audit of this site now. It reads each page in scope one at a time and never changes the site.', 'mlt-schema-audit' ) . '</p>';
			self::button_form( 'mltsa_start', __( 'Start audit', 'mlt-schema-audit' ) );
		}

		$paged = max( 1, self::arg_int( 'paged' ) );
		$runs  = $repo->runs( self::PER_PAGE, ( $paged - 1 ) * self::PER_PAGE );
		echo '<h2>' . esc_html__( 'Audits', 'mlt-schema-audit' ) . '</h2>';
		if ( empty( $runs ) ) {
			echo '<p>' . esc_html__( 'No audits yet.', 'mlt-schema-audit' ) . '</p>';
		} else {
			echo '<table class="widefat striped"><thead><tr><th>Run</th><th>Type</th><th>State</th><th>Started</th><th>Pages read</th><th>Findings</th></tr></thead><tbody>';
			foreach ( $runs as $run ) {
				$summary = Repository::decode( $run['summary'] );
				$read    = isset( $summary['coverage']['ok'] ) ? (int) $summary['coverage']['ok'] : (int) $run['done_count'];
				echo '<tr><td><a href="' . esc_url( self::url( 'mltsa', array( 'run' => (int) $run['id'] ) ) ) . '">#' . (int) $run['id'] . '</a></td>';
				echo '<td>' . esc_html( $run['run_type'] ) . ( ! empty( $summary['is_baseline'] ) ? ' (baseline)' : '' ) . '</td>';
				echo '<td>' . esc_html( Labels::of( Labels::RUN_STATES, $run['state'] ) ) . '</td>';
				echo '<td>' . esc_html( self::when( $run['started_utc'] ? $run['started_utc'] : $run['created_utc'] ) ) . '</td>';
				echo '<td>' . esc_html( $read . ' of ' . (int) $run['url_count'] ) . '</td>';
				echo '<td>' . esc_html( isset( $summary['findings'] ) ? (string) (int) $summary['findings'] : '' ) . '</td></tr>';
			}
			echo '</tbody></table>';
			self::pager( 'mltsa', $paged, $repo->count_runs(), array() );
		}
		self::close();
	}

	/**
	 * Progress panel for the audit in progress; the script keeps it moving.
	 *
	 * @param array $run Run.
	 */
	private static function progress( array $run ) {
		$total = max( 1, (int) $run['url_count'] );
		$pct   = 'discover' === $run['phase'] ? 0 : min( 100, (int) floor( 100 * (int) $run['done_count'] / $total ) );
		echo '<div class="mltsa-progress" id="mltsa-progress" data-run="' . (int) $run['id'] . '">';
		echo '<p><strong>' . esc_html( sprintf( 'Audit #%d is %s.', (int) $run['id'], strtolower( Labels::of( Labels::RUN_STATES, $run['state'] ) ) ) ) . '</strong> ';
		echo '<span id="mltsa-progress-text">' . esc_html( sprintf( '%d of %d pages, phase: %s', (int) $run['done_count'], (int) $run['url_count'], $run['phase'] ) ) . '</span></p>';
		echo '<div class="mltsa-bar"><div class="mltsa-bar-fill" id="mltsa-bar-fill" style="width:' . (int) $pct . '%"></div></div>';
		echo '<p class="description">' . esc_html__( 'Keeping this screen open moves the audit along; it also continues through the scheduler.', 'mlt-schema-audit' ) . '</p>';
		if ( current_user_can( 'mltsa_manage' ) ) {
			self::button_form( 'mltsa_cancel', __( 'Cancel audit', 'mlt-schema-audit' ), array(), 'button' );
		}
		echo '</div>';
	}

	/**
	 * One audit: summary, comparison, exports and pages.
	 *
	 * @param int $run_id Run ID.
	 */
	private static function run_detail( $run_id ) {
		$repo = new Repository();
		$run  = $repo->get_run( $run_id );
		self::open( sprintf( 'Audit #%d', $run_id ) );
		if ( ! $run ) {
			echo '<p>' . esc_html__( 'No such audit.', 'mlt-schema-audit' ) . '</p>';
			self::close();
			return;
		}
		echo '<p><a href="' . esc_url( self::url( 'mltsa' ) ) . '">&larr; ' . esc_html__( 'All audits', 'mlt-schema-audit' ) . '</a></p>';
		if ( in_array( $run['state'], array( 'queued', 'running' ), true ) ) {
			self::progress( $run );
		}
		$summary = Repository::decode( $run['summary'] );
		$scope   = Repository::decode( $run['scope'] );
		$rows    = array(
			'Type'           => $run['run_type'] . ( ! empty( $summary['is_baseline'] ) ? ', baseline' : '' ) . ( ! empty( $scope['catch_up'] ) ? ', catch-up' : '' ),
			'State'          => Labels::of( Labels::RUN_STATES, $run['state'] ),
			'Started'        => self::when( $run['started_utc'] ),
			'Finished'       => self::when( $run['finished_utc'] ),
			'Pages in scope' => (int) $run['url_count'],
			'Pages excluded' => (int) $run['excluded_count'],
			'Rule set'       => $run['ruleset_version'],
			'Compared with'  => (int) $run['baseline_run_id'] ? 'Audit #' . (int) $run['baseline_run_id'] : 'Nothing (first audit)',
		);
		if ( (int) $run['lateness_seconds'] > 300 ) {
			$rows['Started late by'] = human_time_diff( 0, (int) $run['lateness_seconds'] );
		}
		echo '<table class="widefat mltsa-kv"><tbody>';
		foreach ( $rows as $label => $value ) {
			echo '<tr><th>' . esc_html( $label ) . '</th><td>' . esc_html( (string) $value ) . '</td></tr>';
		}
		echo '</tbody></table>';

		if ( ! empty( $summary['coverage'] ) ) {
			echo '<h2>' . esc_html__( 'Coverage', 'mlt-schema-audit' ) . '</h2><ul class="mltsa-list">';
			foreach ( $summary['coverage'] as $state => $n ) {
				echo '<li>' . esc_html( Labels::of( Labels::COVERAGE, $state ) . ': ' . (int) $n ) . '</li>';
			}
			echo '</ul>';
		}
		if ( ! empty( $scope['excluded_by_reason'] ) || ! empty( $scope['status_exclusions'] ) ) {
			echo '<h3>' . esc_html__( 'Left out, with reasons', 'mlt-schema-audit' ) . '</h3><ul class="mltsa-list">';
			foreach ( array_merge( (array) ( isset( $scope['excluded_by_reason'] ) ? $scope['excluded_by_reason'] : array() ), (array) ( isset( $scope['status_exclusions'] ) ? $scope['status_exclusions'] : array() ) ) as $reason => $n ) {
				echo '<li>' . esc_html( str_replace( '_', ' ', $reason ) . ': ' . (int) $n ) . '</li>';
			}
			echo '</ul>';
		}
		if ( ! empty( $summary['comparison'] ) ) {
			echo '<h2>' . esc_html__( 'Compared with the previous audit', 'mlt-schema-audit' ) . '</h2><ul class="mltsa-list">';
			$labels = array(
				'new'             => 'New findings',
				'new_rule_change' => 'New because a rule changed (not a website change)',
				'returned'        => 'Returned',
				'changed'         => 'Changed',
				'resolved'        => 'No longer detected',
				'markup_changed'  => 'Pages with changed markup',
				'pages_added'     => 'Pages added',
				'pages_removed'   => 'Pages removed',
				'coverage_lost'   => 'Pages read last time but not this time',
			);
			foreach ( $labels as $key => $label ) {
				echo '<li>' . esc_html( $label . ': ' . ( isset( $summary['comparison'][ $key ] ) ? (int) $summary['comparison'][ $key ] : 0 ) ) . '</li>';
			}
			echo '</ul>';
			if ( ! empty( $summary['comparison']['rules_changed_ids'] ) ) {
				echo '<p class="description">' . esc_html( 'Rules changed since the baseline: ' . implode( ', ', (array) $summary['comparison']['rules_changed_ids'] ) ) . '</p>';
			}
		}

		if ( ! in_array( $run['state'], array( 'queued', 'running', 'purged' ), true ) ) {
			echo '<h2>' . esc_html__( 'Findings and export', 'mlt-schema-audit' ) . '</h2>';
			echo '<p><a class="button button-primary" href="' . esc_url( self::url( 'mltsa-findings', array( 'run' => $run_id ) ) ) . '">' . esc_html__( 'View findings', 'mlt-schema-audit' ) . '</a> ';
			echo '<a class="button" href="' . esc_url( self::export_url( $run_id, 'zip' ) ) . '">' . esc_html__( 'Download ZIP (all CSV files)', 'mlt-schema-audit' ) . '</a></p><p>';
			foreach ( Exporter::FILES as $file ) {
				echo '<a href="' . esc_url( self::export_url( $run_id, $file ) ) . '">' . esc_html( ucfirst( $file ) . '.csv' ) . '</a> &nbsp; ';
			}
			echo '</p>';
		}

		$coverage = self::arg_key( 'coverage' );
		$paged    = max( 1, self::arg_int( 'paged' ) );
		$urls     = $repo->run_urls( $run_id, self::PER_PAGE, ( $paged - 1 ) * self::PER_PAGE, $coverage );
		echo '<h2>' . esc_html__( 'Pages', 'mlt-schema-audit' ) . '</h2>';
		echo '<table class="widefat striped"><thead><tr><th>Page</th><th>Coverage</th><th>HTTP</th><th>JSON-LD blocks</th><th>Microdata / RDFa</th></tr></thead><tbody>';
		foreach ( $urls as $u ) {
			echo '<tr><td>' . esc_html( $u['url'] ) . ( '' !== $u['title'] ? '<br><span class="description">' . esc_html( $u['title'] ) . '</span>' : '' ) . '</td>';
			echo '<td>' . esc_html( Labels::of( Labels::COVERAGE, $u['coverage'] ) . ( '' !== $u['coverage_reason'] ? ' (' . $u['coverage_reason'] . ')' : '' ) ) . '</td>';
			echo '<td>' . esc_html( (int) $u['http_status'] ? (string) (int) $u['http_status'] : '' ) . '</td>';
			echo '<td>' . esc_html( (string) (int) $u['jsonld_count'] ) . '</td>';
			echo '<td>' . esc_html( (int) $u['microdata'] . ' / ' . (int) $u['rdfa'] ) . '</td></tr>';
		}
		echo '</tbody></table>';
		$counts = $repo->coverage_counts( $run_id );
		self::pager(
			'mltsa',
			$paged,
			'' !== $coverage ? ( isset( $counts[ $coverage ] ) ? $counts[ $coverage ] : 0 ) : array_sum( $counts ),
			array(
				'run'      => $run_id,
				'coverage' => $coverage,
			)
		);
		self::close();
	}

	/**
	 * Export link with a nonce.
	 *
	 * @param int    $run_id Run.
	 * @param string $file   File key or zip.
	 * @param array  $filter Filter.
	 * @return string
	 */
	private static function export_url( $run_id, $file, array $filter = array() ) {
		$args = array_merge(
			array(
				'action' => 'mltsa_export',
				'run'    => (int) $run_id,
				'file'   => $file,
			),
			array_filter( $filter, 'strlen' )
		);
		return wp_nonce_url( add_query_arg( $args, admin_url( 'admin-post.php' ) ), 'mltsa_export' );
	}

	/**
	 * Previous and next links.
	 *
	 * @param string $page  Slug.
	 * @param int    $paged Current page.
	 * @param int    $total Total rows.
	 * @param array  $args  Query args.
	 */
	private static function pager( $page, $paged, $total, array $args ) {
		$pages = max( 1, (int) ceil( $total / self::PER_PAGE ) );
		if ( $pages < 2 ) {
			return;
		}
		$args = array_filter( $args, 'strlen' );
		echo '<p class="mltsa-pager">';
		if ( $paged > 1 ) {
			echo '<a class="button" href="' . esc_url( self::url( $page, $args + array( 'paged' => $paged - 1 ) ) ) . '">&larr; ' . esc_html__( 'Previous', 'mlt-schema-audit' ) . '</a> ';
		}
		echo esc_html( sprintf( 'Page %d of %d', $paged, $pages ) );
		if ( $paged < $pages ) {
			echo ' <a class="button" href="' . esc_url( self::url( $page, $args + array( 'paged' => $paged + 1 ) ) ) . '">' . esc_html__( 'Next', 'mlt-schema-audit' ) . ' &rarr;</a>';
		}
		echo '</p>';
	}

	/* -------------------------------------------------------------- Findings */

	/**
	 * Findings for one audit, or one issue.
	 */
	public static function findings() {
		self::require_cap( 'mltsa_audit' );
		$issue_id = self::arg_int( 'issue' );
		if ( $issue_id ) {
			self::issue_detail( $issue_id );
			return;
		}
		$repo   = new Repository();
		$run_id = self::arg_int( 'run' );
		$runs   = array_values(
			array_filter(
				$repo->runs( 30 ),
				static function ( $r ) {
					return ! in_array( $r['state'], array( 'queued', 'running', 'purged' ), true );
				}
			)
		);
		if ( ! $run_id && ! empty( $runs ) ) {
			$run_id = (int) $runs[0]['id'];
		}
		self::open( __( 'Findings', 'mlt-schema-audit' ) );
		$run = $run_id ? $repo->get_run( $run_id ) : null;
		if ( ! $run ) {
			echo '<p>' . esc_html__( 'No finished audit yet.', 'mlt-schema-audit' ) . '</p>';
			self::close();
			return;
		}
		$filter = array(
			'severity'    => self::arg_key( 'severity' ),
			'rule_id'     => strtoupper( self::arg_key( 'rule_id' ) ),
			'work_status' => self::arg_key( 'work_status' ),
			'display'     => self::arg_key( 'display' ),
			'outcome'     => self::arg_key( 'outcome' ),
		);
		$search = isset( $_GET['s'] ) ? sanitize_text_field( wp_unslash( $_GET['s'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only filter.

		echo '<form method="get" class="mltsa-filters"><input type="hidden" name="page" value="mltsa-findings">';
		echo '<label>Audit <select name="run">';
		foreach ( $runs as $r ) {
			echo '<option value="' . (int) $r['id'] . '"' . selected( (int) $r['id'], $run_id, false ) . '>' . esc_html( '#' . $r['id'] . ' ' . $r['run_type'] . ', ' . self::when( $r['created_utc'] ) ) . '</option>';
		}
		echo '</select></label> ';
		self::select( 'display', 'Group', array_merge( array( '' => 'All' ), Rules::DISPLAY ), $filter['display'] );
		self::select( 'severity', 'Severity', array_merge( array( '' => 'All' ), Labels::SEVERITIES ), $filter['severity'] );
		self::select(
			'outcome',
			'Outcome',
			array(
				''       => 'All',
				'fail'   => 'Fail',
				'review' => 'Review',
			),
			$filter['outcome']
		);
		self::select( 'work_status', 'Status', array_merge( array( '' => 'All' ), Labels::WORK ), $filter['work_status'] );
		$rule_options = array( '' => 'All' );
		foreach ( Rules::catalogue() as $id => $rule ) {
			$rule_options[ strtolower( $id ) ] = $id . ' ' . $rule['title'];
		}
		self::select( 'rule_id', 'Rule', $rule_options, strtolower( $filter['rule_id'] ) );
		echo '<label>Search <input type="search" name="s" value="' . esc_attr( $search ) . '"></label> ';
		echo '<button class="button">' . esc_html__( 'Filter', 'mlt-schema-audit' ) . '</button></form>';

		$query = $filter;
		if ( '' !== $filter['display'] ) {
			$query['rule_ids'] = Exporter::rules_in_display( $filter['display'] );
			if ( empty( $query['rule_ids'] ) ) {
				$query['rule_ids'] = array( '-' );
			}
		}
		$query['search'] = $search;
		$paged           = max( 1, self::arg_int( 'paged' ) );
		$total           = $repo->count_findings( $run_id, $query );
		$rows            = $repo->findings( $run_id, $query, self::PER_PAGE, ( $paged - 1 ) * self::PER_PAGE );
		$filtered        = array_filter( $filter, 'strlen' );

		echo '<p>' . esc_html( sprintf( '%d findings in audit #%d (%s).', $total, $run_id, Labels::of( Labels::RUN_STATES, $run['state'] ) ) ) . ' ';
		echo '<a href="' . esc_url( self::export_url( $run_id, 'zip', $filtered ) ) . '">' . esc_html( empty( $filtered ) ? 'Download ZIP' : 'Download ZIP of this filtered view' ) . '</a></p>';
		if ( 'complete' !== $run['state'] ) {
			echo '<div class="notice notice-warning inline"><p>' . esc_html__( 'This audit did not read every page, so pages it missed show no findings. That is not an all-clear.', 'mlt-schema-audit' ) . '</p></div>';
		}

		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '"><input type="hidden" name="action" value="mltsa_recheck">';
		wp_nonce_field( 'mltsa_recheck' );
		$catalog = Rules::catalogue();
		echo '<table class="widefat striped"><thead><tr><td class="check-column"></td><th>Page</th><th>Finding</th><th>Severity</th><th>Observed</th><th>Status</th><th>Verification</th></tr></thead><tbody>';
		foreach ( $rows as $f ) {
			$rule = isset( $catalog[ $f['rule_id'] ] ) ? $catalog[ $f['rule_id'] ] : null;
			echo '<tr><th class="check-column">' . ( (int) $f['issue_id'] ? '<input type="checkbox" name="issue_ids[]" value="' . (int) $f['issue_id'] . '">' : '' ) . '</th>';
			echo '<td>' . esc_html( (int) $f['site_wide'] && '' === (string) $f['page_url'] ? '(site-wide)' : $f['page_url'] ) . '</td>';
			echo '<td>' . ( (int) $f['issue_id'] ? '<a href="' . esc_url( self::url( 'mltsa-findings', array( 'issue' => (int) $f['issue_id'] ) ) ) . '">' : '' ) . esc_html( $f['rule_id'] . ' ' . ( $rule ? $rule['title'] : '' ) ) . ( (int) $f['issue_id'] ? '</a>' : '' );
			echo '<br><span class="description">' . esc_html( Labels::of( Labels::OUTCOMES, $f['outcome'] ) . ( $rule ? ', ' . Rules::DISPLAY[ $rule['display'] ] : '' ) . ', confidence ' . $f['confidence'] ) . '</span></td>';
			echo '<td>' . esc_html( Labels::of( Labels::SEVERITIES, $f['severity'] ) ) . '</td>';
			echo '<td class="mltsa-evidence">' . esc_html( $f['observed'] ) . '</td>';
			echo '<td>' . esc_html( Labels::of( Labels::WORK, (string) $f['work_status'] ) ) . '</td>';
			echo '<td>' . esc_html( Labels::of( Labels::VERIFICATION, (string) $f['verification_state'] ) ) . '</td></tr>';
		}
		if ( empty( $rows ) ) {
			echo '<tr><td colspan="7">' . esc_html__( 'No findings match.', 'mlt-schema-audit' ) . '</td></tr>';
		}
		echo '</tbody></table>';
		echo '<p><button class="button">' . esc_html__( 'Recheck the pages of the ticked findings', 'mlt-schema-audit' ) . '</button></p></form>';
		self::pager(
			'mltsa-findings',
			$paged,
			$total,
			array_merge(
				$filtered,
				array(
					'run' => $run_id,
					's'   => $search,
				)
			)
		);
		self::close();
	}

	/**
	 * A labelled select for the filter bar.
	 *
	 * @param string $name     Name.
	 * @param string $label    Label.
	 * @param array  $options  value => label.
	 * @param string $selected Selected value.
	 */
	private static function select( $name, $label, array $options, $selected ) {
		echo '<label>' . esc_html( $label ) . ' <select name="' . esc_attr( $name ) . '">';
		foreach ( $options as $value => $text ) {
			echo '<option value="' . esc_attr( $value ) . '"' . selected( (string) $value, (string) $selected, false ) . '>' . esc_html( $text ) . '</option>';
		}
		echo '</select></label> ';
	}

	/**
	 * One issue: rule, evidence, status form, history.
	 *
	 * @param int $issue_id Issue ID.
	 */
	private static function issue_detail( $issue_id ) {
		$repo  = new Repository();
		$issue = $repo->get_issue( $issue_id );
		self::open( sprintf( 'Finding #%d', $issue_id ) );
		if ( ! $issue ) {
			echo '<p>' . esc_html__( 'No such finding.', 'mlt-schema-audit' ) . '</p>';
			self::close();
			return;
		}
		$rule = Rules::get( $issue['rule_id'] );
		echo '<p><a href="' . esc_url( self::url( 'mltsa-findings' ) ) . '">&larr; ' . esc_html__( 'All findings', 'mlt-schema-audit' ) . '</a></p>';
		echo '<h2>' . esc_html( $issue['rule_id'] . ' ' . ( $rule ? $rule['title'] : '' ) ) . '</h2>';
		if ( $rule ) {
			echo '<p>' . esc_html( $rule['explanation'] ) . '</p>';
			echo '<p><strong>' . esc_html__( 'What to check:', 'mlt-schema-audit' ) . '</strong> ' . esc_html( $rule['investigate'] ) . '</p>';
			echo '<p class="description">' . esc_html( sprintf( '%s. %s. Rule version %d, reviewed %s. Source: ', Rules::GROUPS[ $rule['group'] ], Rules::DISPLAY[ $rule['display'] ], (int) $issue['rule_version'], $rule['reviewed'] ) ) . '<a href="' . esc_url( $rule['source'] ) . '" rel="noopener noreferrer" target="_blank">' . esc_html( $rule['source'] ) . '</a></p>';
		}
		$occurrence = (int) $issue['latest_occurrence_id'] ? $repo->occurrence( (int) $issue['latest_occurrence_id'] ) : null;
		$facts      = array(
			'Page'               => (int) $issue['site_wide'] ? '(site-wide)' : $issue['page_url'],
			'Entity'             => $issue['entity_key'],
			'Property'           => $issue['property'],
			'Severity'           => Labels::of( Labels::SEVERITIES, $issue['severity'] ),
			'Verification state' => Labels::of( Labels::VERIFICATION, $issue['verification_state'] ) . ( 'rule_change' === $issue['change_reason'] ? ' (rule change, not a website change)' : '' ),
			'First observed'     => self::when( $issue['first_observed_utc'] ),
			'Last observed'      => self::when( $issue['last_observed_utc'] ),
			'Last verified in'   => (int) $issue['verification_run_id'] ? 'Audit #' . (int) $issue['verification_run_id'] : '',
		);
		echo '<table class="widefat mltsa-kv"><tbody>';
		foreach ( $facts as $label => $value ) {
			echo '<tr><th>' . esc_html( $label ) . '</th><td>' . esc_html( (string) $value ) . '</td></tr>';
		}
		echo '</tbody></table>';
		if ( $occurrence ) {
			echo '<h3>' . esc_html__( 'Evidence', 'mlt-schema-audit' ) . '</h3><table class="widefat mltsa-kv"><tbody>';
			foreach ( array(
				'Observed'       => $occurrence['observed'],
				'Compared with'  => $occurrence['comparison'],
				'Block and path' => ( (int) $occurrence['block_index'] >= 0 ? 'Block ' . ( (int) $occurrence['block_index'] + 1 ) . ', ' : '' ) . $occurrence['json_path'],
				'Source'         => $occurrence['source'] . ' (' . $occurrence['source_confidence'] . ' confidence)',
			) as $label => $value ) {
				echo '<tr><th>' . esc_html( $label ) . '</th><td class="mltsa-evidence">' . esc_html( (string) $value ) . '</td></tr>';
			}
			echo '</tbody></table>';
			if ( '' !== $occurrence['snippet'] ) {
				echo '<pre class="mltsa-pre">' . esc_html( $occurrence['snippet'] ) . '</pre>';
			}
		} elseif ( (int) $issue['latest_occurrence_id'] ) {
			echo '<p class="description">' . esc_html__( 'The evidence for this finding was removed by retention.', 'mlt-schema-audit' ) . '</p>';
		}

		echo '<h3>' . esc_html__( 'Work status', 'mlt-schema-audit' ) . '</h3>';
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" class="mltsa-form"><input type="hidden" name="action" value="mltsa_issue"><input type="hidden" name="issue_id" value="' . (int) $issue_id . '">';
		wp_nonce_field( 'mltsa_issue_' . $issue_id );
		echo '<p><label>Status <select name="work_status">';
		foreach ( Labels::WORK as $value => $label ) {
			echo '<option value="' . esc_attr( $value ) . '"' . selected( $value, $issue['work_status'], false ) . '>' . esc_html( $label ) . '</option>';
		}
		echo '</select></label></p>';
		echo '<p><label>Owner ';
		wp_dropdown_users(
			array(
				'name'              => 'owner_user_id',
				'selected'          => (int) $issue['owner_user_id'],
				'show_option_none'  => 'Nobody',
				'option_none_value' => 0,
				'capability'        => 'mltsa_audit',
			)
		);
		echo '</label></p>';
		echo '<p><label>Due date <input type="date" name="due_date" value="' . esc_attr( (string) $issue['due_date'] ) . '"></label></p>';
		echo '<p><label>External task link <input type="url" name="external_link" class="regular-text" value="' . esc_attr( $issue['external_link'] ) . '" placeholder="https://"></label></p>';
		echo '<fieldset class="mltsa-exception"><legend>' . esc_html__( 'Needed for an accepted exception or a false positive', 'mlt-schema-audit' ) . '</legend>';
		echo '<p><label>Reason<br><textarea name="exception_reason" rows="2" class="large-text">' . esc_textarea( $issue['exception_reason'] ) . '</textarea></label></p>';
		echo '<p><label>Reviewer <input type="text" name="exception_reviewer" value="' . esc_attr( $issue['exception_reviewer'] ) . '"></label> ';
		echo '<label>Review date <input type="date" name="exception_review_date" value="' . esc_attr( (string) $issue['exception_review_date'] ) . '"></label></p></fieldset>';
		echo '<p><label>Add a note (client staff with access can read notes)<br><textarea name="note" rows="3" class="large-text"></textarea></label></p>';
		echo '<p><button class="button button-primary">' . esc_html__( 'Save', 'mlt-schema-audit' ) . '</button></p></form>';
		if ( ! (int) $issue['site_wide'] ) {
			self::button_form( 'mltsa_recheck', __( 'Recheck this page now', 'mlt-schema-audit' ), array( 'issue_ids[]' => (int) $issue_id ), 'button' );
		}
		echo '<p class="description">' . esc_html__( 'Marking a finding Resolved does not verify it. Only a recheck or a monthly audit can show it as no longer detected.', 'mlt-schema-audit' ) . '</p>';

		echo '<h3>' . esc_html__( 'History', 'mlt-schema-audit' ) . '</h3><table class="widefat striped"><thead><tr><th>When</th><th>By</th><th>What</th></tr></thead><tbody>';
		foreach ( $repo->events_for( 'issue', $issue_id ) as $event ) {
			$data  = Repository::decode( $event['data'] );
			$actor = (int) $event['actor_user_id'] ? get_userdata( (int) $event['actor_user_id'] ) : false;
			$what  = 'note' === $event['event_type'] ? 'Note: ' . ( isset( $data['text'] ) ? $data['text'] : '' ) : str_replace( '_', ' ', $event['event_type'] ) . ' ' . (string) wp_json_encode( $data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE );
			echo '<tr><td>' . esc_html( self::when( $event['created_utc'] ) ) . '</td><td>' . esc_html( $actor ? $actor->display_name : 'Scanner' ) . '</td><td class="mltsa-evidence">' . esc_html( $what ) . '</td></tr>';
		}
		echo '</tbody></table>';
		self::close();
	}

	/* -------------------------------------------------------------- Settings */

	/**
	 * Settings screen.
	 */
	public static function settings() {
		self::require_cap( 'mltsa_manage' );
		$s = Settings::all();
		self::open( __( 'Schema Audit settings', 'mlt-schema-audit' ) );
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" class="mltsa-form"><input type="hidden" name="action" value="mltsa_settings">';
		wp_nonce_field( 'mltsa_settings' );

		echo '<h2>' . esc_html__( 'Scope', 'mlt-schema-audit' ) . '</h2><p>' . esc_html__( 'The homepage is always audited. Choose the published content types to include. Drafts, private and password-protected content are never audited.', 'mlt-schema-audit' ) . '</p><p>';
		foreach ( get_post_types( array( 'public' => true ), 'objects' ) as $type ) {
			if ( 'attachment' === $type->name ) {
				continue;
			}
			echo '<label class="mltsa-check"><input type="checkbox" name="post_types[]" value="' . esc_attr( $type->name ) . '"' . checked( in_array( $type->name, (array) $s['post_types'], true ), true, false ) . '> ' . esc_html( $type->labels->name ) . '</label> ';
		}
		echo '</p>';
		self::checkbox( 'sitemap_discovery', 'Also read URLs from this site\'s own sitemaps (capped)', $s );
		echo '<p><label>Most pages per audit <input type="number" name="max_urls" min="1" max="5000" value="' . (int) $s['max_urls'] . '"></label></p>';
		self::checkbox( 'scope_confirmed', 'The scope is confirmed', $s );

		echo '<h2>' . esc_html__( 'Monthly schedule', 'mlt-schema-audit' ) . '</h2><p>';
		echo '<select name="schedule_ordinal">';
		foreach ( Settings::ORDINALS as $o ) {
			echo '<option value="' . esc_attr( $o ) . '"' . selected( $o, $s['schedule_ordinal'], false ) . '>' . esc_html( ucfirst( $o ) ) . '</option>';
		}
		echo '</select> <select name="schedule_weekday">';
		foreach ( Settings::WEEKDAYS as $d ) {
			echo '<option value="' . esc_attr( $d ) . '"' . selected( $d, $s['schedule_weekday'], false ) . '>' . esc_html( ucfirst( $d ) ) . '</option>';
		}
		echo '</select> of the month at <input type="time" name="schedule_time" value="' . esc_attr( $s['schedule_time'] ) . '"> <select name="schedule_timezone">';
		foreach ( array_unique( array( 'Europe/London', (string) $s['schedule_timezone'], 'UTC' ) ) as $tz ) {
			echo '<option value="' . esc_attr( $tz ) . '"' . selected( $tz, $s['schedule_timezone'], false ) . '>' . esc_html( $tz ) . '</option>';
		}
		echo '</select></p><p class="description">' . esc_html__( 'Next three start times:', 'mlt-schema-audit' ) . ' ';
		$dates = array();
		foreach ( Scheduler::next_dates( $s ) as $ts ) {
			$dates[] = wp_date( 'l j F Y, H:i T', $ts, new \DateTimeZone( $s['schedule_timezone'] ) );
		}
		echo esc_html( implode( '; ', $dates ) ) . '. ' . esc_html__( 'The time is when the audit starts; the email follows when it finishes. Stagger sites on the same server across the first week.', 'mlt-schema-audit' ) . '</p>';
		self::checkbox( 'schedule_confirmed', 'The schedule is confirmed', $s );

		echo '<h2>' . esc_html__( 'Recipients', 'mlt-schema-audit' ) . '</h2>';
		echo '<p><label>' . esc_html__( 'One email address per line (at most 10). The site admin address is never used.', 'mlt-schema-audit' ) . '<br><textarea name="recipients" rows="3" class="large-text">' . esc_textarea( implode( "\n", (array) $s['recipients'] ) ) . '</textarea></label></p>';
		if ( ! empty( $s['recipients'] ) && Settings::mail_paused() ) {
			echo '<div class="notice notice-error inline"><p>' . esc_html( sprintf( 'Mail is paused: these recipients were confirmed on %s, and this site is now %s.', $s['recipients_home'], home_url( '/' ) ) ) . '</p></div>';
			self::checkbox( 'reconfirm_recipients', 'Reconfirm these recipients for ' . home_url( '/' ), array( 'reconfirm_recipients' => false ) );
		} elseif ( ! empty( $s['recipients'] ) ) {
			echo '<p class="description">' . esc_html( sprintf( 'Confirmed on %s, %s.', $s['recipients_home'], self::when( $s['recipients_confirmed_utc'] ) ) ) . '</p>';
		}
		self::checkbox( 'notify_no_change', 'Also email when nothing changed (off by default)', $s );

		echo '<h2>' . esc_html__( 'Monitoring', 'mlt-schema-audit' ) . '</h2>';
		$blockers = Settings::monitoring_blockers();
		if ( ! empty( $blockers ) && empty( $s['monitoring'] ) ) {
			echo '<p class="description">' . esc_html( 'Before monitoring can be switched on: ' . implode( ' ', $blockers ) ) . '</p>';
		}
		self::checkbox( 'monitoring', 'Run the monthly audit and send the email', $s );
		self::checkbox( 'kill_switch', 'Kill switch: stop scheduling and mail now (manual audits still work)', $s );

		echo '<h2>' . esc_html__( 'Fact reference (optional)', 'mlt-schema-audit' ) . '</h2>';
		echo '<p><label>' . esc_html__( 'Approved telephone numbers, one per line', 'mlt-schema-audit' ) . '<br><textarea name="approved_phones" rows="3" class="large-text">' . esc_textarea( implode( "\n", array_map( array( \MLT\SchemaAudit\Engine\Evaluator::class, 'display_nsn' ), (array) $s['approved_phones'] ) ) ) . '</textarea></label></p>';
		echo '<p><label>' . esc_html__( 'Approved business names, one per line', 'mlt-schema-audit' ) . '<br><textarea name="approved_names" rows="3" class="large-text">' . esc_textarea( implode( "\n", (array) $s['approved_names'] ) ) . '</textarea></label></p>';
		echo '<p><label>' . esc_html__( 'Extra staging or development hosts, one per line', 'mlt-schema-audit' ) . '<br><textarea name="staging_patterns" rows="2" class="large-text">' . esc_textarea( implode( "\n", (array) $s['staging_patterns'] ) ) . '</textarea></label></p>';

		echo '<h2>' . esc_html__( 'Limits and data', 'mlt-schema-audit' ) . '</h2>';
		echo '<p><label>Seconds between requests <input type="number" name="gap_seconds" min="0" max="30" value="' . (int) $s['gap_seconds'] . '"></label> ';
		echo '<label>Timeout per request (seconds) <input type="number" name="timeout" min="5" max="60" value="' . (int) $s['timeout'] . '"></label></p>';
		echo '<p><label>Monthly audits kept with full evidence (at least 13) <input type="number" name="retention_runs" min="13" max="120" value="' . (int) $s['retention_runs'] . '"></label></p>';
		self::checkbox( 'remove_data_on_uninstall', 'Remove all audit data when the plugin is deleted', $s );
		echo '<p><button class="button button-primary">' . esc_html__( 'Save settings', 'mlt-schema-audit' ) . '</button></p></form>';
		self::close();
	}

	/**
	 * A labelled checkbox.
	 *
	 * @param string $name  Setting.
	 * @param string $label Label.
	 * @param array  $s     Settings.
	 */
	private static function checkbox( $name, $label, array $s ) {
		echo '<p><label class="mltsa-check"><input type="checkbox" name="' . esc_attr( $name ) . '" value="1"' . checked( ! empty( $s[ $name ] ), true, false ) . '> ' . esc_html( $label ) . '</label></p>';
	}

	/* ---------------------------------------------------------------- Health */

	/**
	 * Health screen.
	 */
	public static function health() {
		self::require_cap( 'mltsa_audit' );
		self::open( __( 'Schema Audit health', 'mlt-schema-audit' ) );
		echo '<table class="widefat striped mltsa-health"><tbody>';
		foreach ( Health::checks() as $check ) {
			echo '<tr class="mltsa-' . esc_attr( $check['status'] ) . '"><th>' . esc_html( strtoupper( $check['status'] ) ) . '</th><td><strong>' . esc_html( $check['label'] ) . '</strong><br>' . esc_html( $check['detail'] ) . '</td></tr>';
		}
		echo '</tbody></table>';
		$repo = new Repository();
		echo '<h2>' . esc_html__( 'Recent notifications', 'mlt-schema-audit' ) . '</h2><table class="widefat striped"><thead><tr><th>Audit</th><th>Type</th><th>Recipient</th><th>State</th><th>Attempts</th><th>Updated</th></tr></thead><tbody>';
		foreach ( $repo->recent_outbox( 20 ) as $row ) {
			echo '<tr><td>#' . (int) $row['run_id'] . '</td><td>' . esc_html( $row['notification_type'] ) . '</td><td>' . esc_html( $row['recipient'] ) . '</td><td>' . esc_html( str_replace( '_', ' ', $row['state'] ) . ( '' !== $row['last_error'] ? ' (' . $row['last_error'] . ')' : '' ) ) . '</td><td>' . (int) $row['attempts'] . '</td><td>' . esc_html( self::when( $row['updated_utc'] ? $row['updated_utc'] : $row['created_utc'] ) ) . '</td></tr>';
		}
		echo '</tbody></table>';
		echo '<h2>' . esc_html__( 'Recent settings and control changes', 'mlt-schema-audit' ) . '</h2><table class="widefat striped"><thead><tr><th>When</th><th>By</th><th>Change</th></tr></thead><tbody>';
		foreach ( $repo->recent_events( 20, array( 'settings_changed', 'recipients_changed', 'recipients_reconfirmed', 'kill_switch_changed', 'outbox_rebuilt', 'mail_suppressed', 'run_cancelled', 'retention' ) ) as $event ) {
			$actor = (int) $event['actor_user_id'] ? get_userdata( (int) $event['actor_user_id'] ) : false;
			echo '<tr><td>' . esc_html( self::when( $event['created_utc'] ) ) . '</td><td>' . esc_html( $actor ? $actor->display_name : 'System' ) . '</td><td class="mltsa-evidence">' . esc_html( str_replace( '_', ' ', $event['event_type'] ) . ' ' . $event['data'] ) . '</td></tr>';
		}
		echo '</tbody></table>';
		self::close();
	}
}
