<?php
/**
 * Staff changes to the issue register: work status, owner, due date,
 * external link and notes (contract section 6). Every change is logged.
 * Verification state is never set here; only the scanner sets it.
 *
 * @package MLT\SchemaAudit
 */

namespace MLT\SchemaAudit;

use MLT\SchemaAudit\Store\Repository;

defined( 'ABSPATH' ) || exit;

/**
 * Issues.
 */
class Issues {

	/**
	 * Longest note kept.
	 */
	const MAX_NOTE = 2000;

	/**
	 * Validate a requested change. Pure, so it is unit tested.
	 *
	 * @param array $issue   Current issue row.
	 * @param array $request { work_status, owner_user_id, due_date, external_link, exception_reason, exception_reviewer, exception_review_date }.
	 * @return array { fields: changes to save, errors: list }
	 */
	public static function validate( array $issue, array $request ) {
		$fields = array();
		$errors = array();
		$status = isset( $request['work_status'] ) ? (string) $request['work_status'] : $issue['work_status'];
		if ( ! isset( Labels::WORK[ $status ] ) ) {
			$errors[] = 'Unknown work status.';
			$status   = $issue['work_status'];
		}
		if ( $status !== $issue['work_status'] ) {
			$fields['work_status'] = $status;
		}
		if ( in_array( $status, Labels::NEEDS_REASON, true ) ) {
			$reason   = trim( isset( $request['exception_reason'] ) ? (string) $request['exception_reason'] : (string) $issue['exception_reason'] );
			$reviewer = trim( isset( $request['exception_reviewer'] ) ? (string) $request['exception_reviewer'] : (string) $issue['exception_reviewer'] );
			$date     = trim( isset( $request['exception_review_date'] ) ? (string) $request['exception_review_date'] : (string) $issue['exception_review_date'] );
			if ( '' === $reason || '' === $reviewer || ! self::is_date( $date ) ) {
				$errors[] = 'An accepted exception or false positive needs a reason, a reviewer and a review date.';
			} else {
				$fields['exception_reason']      = substr( $reason, 0, 1000 );
				$fields['exception_reviewer']    = substr( $reviewer, 0, 100 );
				$fields['exception_review_date'] = $date;
			}
		}
		if ( isset( $request['owner_user_id'] ) && (int) $request['owner_user_id'] !== (int) $issue['owner_user_id'] ) {
			$fields['owner_user_id'] = max( 0, (int) $request['owner_user_id'] );
		}
		if ( isset( $request['due_date'] ) ) {
			$due = trim( (string) $request['due_date'] );
			if ( '' === $due ) {
				if ( null !== $issue['due_date'] && '' !== (string) $issue['due_date'] ) {
					$fields['due_date'] = null;
				}
			} elseif ( ! self::is_date( $due ) ) {
				$errors[] = 'The due date must be a date (YYYY-MM-DD).';
			} elseif ( $due !== (string) $issue['due_date'] ) {
				$fields['due_date'] = $due;
			}
		}
		if ( isset( $request['external_link'] ) ) {
			$link = trim( (string) $request['external_link'] );
			if ( '' !== $link && ! preg_match( '#^https://[^\s<>"]+$#i', $link ) ) {
				$errors[] = 'The external task link must be an https address.';
			} elseif ( $link !== (string) $issue['external_link'] ) {
				$fields['external_link'] = substr( $link, 0, 2048 );
			}
		}
		if ( ! empty( $errors ) ) {
			$fields = array();
		}
		return array(
			'fields' => $fields,
			'errors' => $errors,
		);
	}

	/**
	 * Whether a value is a real calendar date in Y-m-d form.
	 *
	 * @param string $value Value.
	 * @return bool
	 */
	public static function is_date( $value ) {
		if ( ! preg_match( '/^(\d{4})-(\d{2})-(\d{2})$/', (string) $value, $m ) ) {
			return false;
		}
		return checkdate( (int) $m[2], (int) $m[3], (int) $m[1] );
	}

	/**
	 * Apply a change and a note, logging each.
	 *
	 * @param int    $issue_id Issue ID.
	 * @param array  $request  Request.
	 * @param string $note     Note text.
	 * @param int    $user_id  User.
	 * @return array { saved: bool, errors: list }
	 */
	public static function update( $issue_id, array $request, $note, $user_id ) {
		$repo  = new Repository();
		$issue = $repo->get_issue( $issue_id );
		if ( ! $issue ) {
			return array(
				'saved'  => false,
				'errors' => array( 'Issue not found.' ),
			);
		}
		$result = self::validate( $issue, $request );
		if ( ! empty( $result['errors'] ) ) {
			return array(
				'saved'  => false,
				'errors' => $result['errors'],
			);
		}
		$saved = false;
		if ( ! empty( $result['fields'] ) ) {
			$repo->update_issue( (int) $issue_id, $result['fields'] );
			$changes = array();
			foreach ( $result['fields'] as $key => $value ) {
				$changes[ $key ] = array(
					'from' => isset( $issue[ $key ] ) ? $issue[ $key ] : null,
					'to'   => $value,
				);
			}
			$repo->log_event( 'status_changed', $changes, $user_id, 'issue', (int) $issue_id );
			$saved = true;
		}
		$note = trim( (string) $note );
		if ( '' !== $note ) {
			$repo->log_event( 'note', array( 'text' => function_exists( 'mb_substr' ) ? mb_substr( $note, 0, self::MAX_NOTE ) : substr( $note, 0, self::MAX_NOTE ) ), $user_id, 'issue', (int) $issue_id );
			$saved = true;
		}
		return array(
			'saved'  => $saved,
			'errors' => array(),
		);
	}

	/**
	 * The latest note on each issue.
	 *
	 * @param array $issue_ids Issue IDs.
	 * @return array issue_id => text
	 */
	public static function latest_notes( array $issue_ids ) {
		$repo = new Repository();
		$out  = array();
		foreach ( array_unique( array_map( 'intval', $issue_ids ) ) as $id ) {
			foreach ( $repo->events_for( 'issue', $id ) as $event ) {
				if ( 'note' === $event['event_type'] ) {
					$data       = Repository::decode( $event['data'] );
					$out[ $id ] = isset( $data['text'] ) ? (string) $data['text'] : '';
				}
			}
		}
		return $out;
	}
}
