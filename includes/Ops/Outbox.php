<?php
/**
 * The outbox: one row per notification per run per recipient (M4, M6).
 *
 * States: pending, sending, submitted, failed, delivery_unknown, cancelled.
 * A row is claimed atomically before wp_mail() is called. If the process
 * dies while a row is "sending", the claim expires and the row becomes
 * delivery_unknown, never retried blindly. Mail goes through wp_mail() only,
 * with fixed headers, and the plugin registers no mail filters (M5).
 *
 * @package MLT\SchemaAudit
 */

namespace MLT\SchemaAudit\Ops;

use MLT\SchemaAudit\Settings;
use MLT\SchemaAudit\Store\Repository;

defined( 'ABSPATH' ) || exit;

/**
 * Outbox.
 */
class Outbox {

	/**
	 * Attempts before a row is marked failed.
	 */
	const MAX_ATTEMPTS = 3;

	/**
	 * Seconds a claim is held.
	 */
	const CLAIM_TTL = 120;

	/**
	 * Hash of a recipient list, so rows built for an older list can be told apart.
	 *
	 * @param array $recipients Recipients.
	 * @return string
	 */
	public static function recipients_hash( array $recipients ) {
		sort( $recipients );
		return sha1( implode( ',', $recipients ) );
	}

	/**
	 * Queue the notification a finished monthly run needs.
	 *
	 * @param array $run Run row.
	 * @return int Rows queued.
	 */
	public static function queue_for_run( array $run ) {
		$repo    = new Repository();
		$summary = Repository::decode( $run['summary'] );
		$type    = Digest::type_for( $run, $summary, (bool) Settings::get( 'notify_no_change' ) );
		if ( '' === $type ) {
			return 0;
		}
		if ( Settings::is_disabled() ) {
			$repo->log_event( 'mail_suppressed', array( 'reason' => 'kill_switch' ), 0, 'run', (int) $run['id'], (int) $run['id'] );
			return 0;
		}
		$recipients = (array) Settings::get( 'recipients' );
		if ( empty( $recipients ) ) {
			// No fallback to admin_email, ever (M4). The health screen shows it.
			$repo->log_event( 'mail_suppressed', array( 'reason' => 'no_recipients' ), 0, 'run', (int) $run['id'], (int) $run['id'] );
			return 0;
		}
		$hash   = self::recipients_hash( $recipients );
		$queued = 0;
		foreach ( $recipients as $recipient ) {
			$queued += $repo->insert_outbox(
				array(
					'run_id'            => (int) $run['id'],
					'notification_type' => $type,
					'recipient'         => $recipient,
					'recipients_hash'   => $hash,
					'state'             => 'pending',
				)
			) ? 1 : 0;
		}
		if ( $queued ) {
			wp_schedule_single_event( time(), Scheduler::OUTBOX_HOOK );
		}
		return $queued;
	}

	/**
	 * Recipients changed before unsent notifications went out: cancel rows
	 * for removed recipients, add rows for new ones, log the change.
	 *
	 * @param int $user_id User.
	 */
	public static function rebuild_pending( $user_id ) {
		$repo       = new Repository();
		$recipients = (array) Settings::get( 'recipients' );
		$hash       = self::recipients_hash( $recipients );
		$pending    = $repo->outbox_in( array( 'pending' ), 1000 );
		$groups     = array();
		$cancelled  = 0;
		$added      = 0;
		foreach ( $pending as $row ) {
			$groups[ $row['run_id'] . '|' . $row['notification_type'] ] = array( (int) $row['run_id'], $row['notification_type'] );
			if ( in_array( $row['recipient'], $recipients, true ) ) {
				$repo->update_outbox( (int) $row['id'], array( 'recipients_hash' => $hash ) );
			} else {
				$repo->update_outbox(
					(int) $row['id'],
					array(
						'state'      => 'cancelled',
						'last_error' => 'recipient_removed',
					)
				);
				++$cancelled;
			}
		}
		foreach ( $groups as $group ) {
			foreach ( $recipients as $recipient ) {
				$added += $repo->insert_outbox(
					array(
						'run_id'            => $group[0],
						'notification_type' => $group[1],
						'recipient'         => $recipient,
						'recipients_hash'   => $hash,
						'state'             => 'pending',
					)
				) ? 1 : 0;
			}
		}
		if ( $cancelled || $added ) {
			$repo->log_event(
				'outbox_rebuilt',
				array(
					'cancelled' => $cancelled,
					'added'     => $added,
				),
				$user_id
			);
		}
	}

	/**
	 * Why mail cannot go now, or ''.
	 *
	 * @return string
	 */
	public static function blocked_reason() {
		if ( Settings::is_disabled() ) {
			return 'kill_switch';
		}
		if ( empty( Settings::get( 'recipients' ) ) ) {
			return 'no_recipients';
		}
		if ( Settings::mail_paused() ) {
			return 'home_url_changed';
		}
		return '';
	}

	/**
	 * Send what is due.
	 *
	 * @param int $limit Most rows this call.
	 * @return array { submitted, failed, unknown, blocked }
	 */
	public static function process( $limit = 20 ) {
		$repo  = new Repository();
		$stats = array(
			'submitted' => 0,
			'failed'    => 0,
			'unknown'   => 0,
			'blocked'   => '',
		);

		foreach ( $repo->outbox_in( array( 'sending' ), 100 ) as $row ) {
			if ( (int) $row['claimed_until'] < time() ) {
				$repo->update_outbox(
					(int) $row['id'],
					array(
						'state'      => 'delivery_unknown',
						'last_error' => 'claim_expired_during_send',
					),
					$row['claim_token']
				);
				++$stats['unknown'];
			}
		}

		$blocked = self::blocked_reason();
		if ( '' !== $blocked ) {
			$stats['blocked'] = $blocked;
			update_option( 'mltsa_mail_blocked', $blocked, false );
			return $stats;
		}
		delete_option( 'mltsa_mail_blocked' );

		$hash = self::recipients_hash( (array) Settings::get( 'recipients' ) );
		foreach ( $repo->outbox_in( array( 'pending' ), $limit ) as $row ) {
			if ( (int) $row['not_before'] > time() ) {
				continue;
			}
			if ( $row['recipients_hash'] !== $hash ) {
				$repo->update_outbox(
					(int) $row['id'],
					array(
						'state'      => 'cancelled',
						'last_error' => 'recipients_changed',
					)
				);
				continue;
			}
			$token = wp_generate_password( 20, false );
			if ( ! $repo->claim_outbox( (int) $row['id'], $token, self::CLAIM_TTL ) ) {
				continue;
			}
			$message = self::message( $row );
			if ( null === $message ) {
				$repo->update_outbox(
					(int) $row['id'],
					array(
						'state'      => 'cancelled',
						'last_error' => 'run_missing',
					),
					$token
				);
				continue;
			}
			$sent = wp_mail( $row['recipient'], $message['subject'], $message['body'], Digest::headers() );
			if ( $sent ) {
				$repo->update_outbox(
					(int) $row['id'],
					array(
						'state'         => 'submitted',
						'submitted_utc' => Repository::now(),
						'last_error'    => '',
					),
					$token
				);
				++$stats['submitted'];
				continue;
			}
			$attempts = (int) $row['attempts'] + 1;
			$repo->update_outbox(
				(int) $row['id'],
				array(
					'state'      => $attempts >= self::MAX_ATTEMPTS ? 'failed' : 'pending',
					'not_before' => time() + 300 * $attempts,
					'last_error' => 'wp_mail_returned_false',
				),
				$token
			);
			++$stats['failed'];
		}
		return $stats;
	}

	/**
	 * Build the message for one row.
	 *
	 * @param array $row Outbox row.
	 * @return array|null { subject, body }
	 */
	public static function message( array $row ) {
		$repo = new Repository();
		$run  = $repo->get_run( (int) $row['run_id'] );
		if ( ! $run ) {
			return null;
		}
		$summary  = Repository::decode( $run['summary'] );
		$coverage = isset( $summary['coverage'] ) ? (array) $summary['coverage'] : array();
		$unknown  = 0;
		foreach ( \MLT\SchemaAudit\Engine\Comparator::UNKNOWN as $state ) {
			$unknown += isset( $coverage[ $state ] ) ? (int) $coverage[ $state ] : 0;
		}
		$host = (string) wp_parse_url( home_url( '/' ), PHP_URL_HOST );
		$date = wp_date( 'Y-m-d', strtotime( $run['created_utc'] . ' UTC' ), new \DateTimeZone( (string) Settings::get( 'schedule_timezone' ) ) );
		$data = array(
			'host'              => $host,
			'date'              => $date,
			'type'              => $row['notification_type'],
			'state'             => $run['state'],
			'pages_read'        => isset( $coverage['ok'] ) ? (int) $coverage['ok'] : 0,
			'pages_total'       => (int) $run['url_count'],
			'pages_unavailable' => $unknown,
			'findings'          => isset( $summary['findings'] ) ? (int) $summary['findings'] : 0,
			'comparison'        => isset( $summary['comparison'] ) ? (array) $summary['comparison'] : array(),
			'link'              => admin_url( 'admin.php?page=mltsa&run=' . (int) $run['id'] ),
		);
		return array(
			'subject' => Digest::subject( $host, $date, $row['notification_type'] ),
			'body'    => Digest::body( $data ),
		);
	}
}
