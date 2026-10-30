<?php
/**
 * WP-CLI commands. `wp mltsa tick` is the recommended server cron entry
 * point: it runs the scheduler and worker with a long budget, so a large
 * site finishes in a few cron intervals instead of many web requests.
 *
 * @package MLT\SchemaAudit
 */

namespace MLT\SchemaAudit;

defined( 'ABSPATH' ) || exit;

/**
 * Audit the structured data in this site's server responses.
 */
class Cli {

	/**
	 * Run the scheduler, the active audit and the outbox.
	 *
	 * ## OPTIONS
	 *
	 * [--budget=<seconds>]
	 * : How long to work. Default 240, for a cron job every five minutes.
	 *
	 * @param array $args       Positional.
	 * @param array $assoc_args Named.
	 */
	public function tick( $args, $assoc_args ) {
		$budget = isset( $assoc_args['budget'] ) ? max( 5, min( 3600, (int) $assoc_args['budget'] ) ) : 240;
		$status = Ops\Worker::tick( $budget );
		\WP_CLI::log( (string) wp_json_encode( $status ) );
	}

	/**
	 * Start a manual audit.
	 *
	 * ## OPTIONS
	 *
	 * [--wait]
	 * : Keep working until the audit finishes.
	 *
	 * @param array $args       Positional.
	 * @param array $assoc_args Named.
	 */
	public function audit( $args, $assoc_args ) {
		$id = Ops\Scheduler::start_manual( 0 );
		if ( ! $id ) {
			\WP_CLI::error( 'Refused: another audit is in progress, or MLTSA_DISABLE is set.' );
		}
		\WP_CLI::log( 'Started run ' . $id );
		if ( empty( $assoc_args['wait'] ) ) {
			return;
		}
		$worker = new Ops\Worker();
		do {
			$status = $worker->process( $id, 60 );
			\WP_CLI::log( sprintf( '%s %s %d/%d', $status['state'], $status['phase'], $status['done'], $status['total'] ) );
		} while ( in_array( $status['state'], array( 'queued', 'running' ), true ) && 'locked' !== $status['note'] );
	}

	/**
	 * Show the latest runs and the health checks.
	 *
	 * @param array $args       Positional.
	 * @param array $assoc_args Named.
	 */
	public function status( $args, $assoc_args ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.FoundAfterLastUsed -- WP-CLI passes both arguments to every command.
		$repo = new Store\Repository();
		foreach ( $repo->runs( 5 ) as $run ) {
			\WP_CLI::log( sprintf( '#%d %s %s %s %d/%d', $run['id'], $run['run_type'], $run['state'], $run['phase'], $run['done_count'], $run['url_count'] ) );
		}
		foreach ( Admin\Health::checks() as $check ) {
			\WP_CLI::log( sprintf( '[%s] %s: %s', $check['status'], $check['label'], $check['detail'] ) );
		}
	}
}
