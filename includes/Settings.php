<?php
/**
 * Plugin settings: one option, mltsa_settings, never autoloaded.
 *
 * Every change goes through update(), which sanitises the values and writes
 * one event per changed group (contract section 3, events). Recipient
 * changes are logged separately because they decide where mail goes.
 *
 * @package MLT\SchemaAudit
 */

namespace MLT\SchemaAudit;

use MLT\SchemaAudit\Engine\PageFacts;
use MLT\SchemaAudit\Store\Repository;

defined( 'ABSPATH' ) || exit;

/**
 * Settings.
 */
class Settings {

	/**
	 * Option name.
	 */
	const OPTION = 'mltsa_settings';

	/**
	 * Allowed week ordinals for the schedule.
	 */
	const ORDINALS = array( 'first', 'second', 'third', 'fourth', 'last' );

	/**
	 * Allowed weekdays.
	 */
	const WEEKDAYS = array( 'monday', 'tuesday', 'wednesday', 'thursday', 'friday' );

	/**
	 * Most recipients allowed.
	 */
	const MAX_RECIPIENTS = 10;

	/**
	 * Cached settings for the request.
	 *
	 * @var array|null
	 */
	private static $cache = null;

	/**
	 * Defaults. Anything marked Proposed in the contract is here.
	 *
	 * @return array
	 */
	public static function defaults() {
		return array(
			'monitoring'               => false,
			'kill_switch'              => false,
			'recipients'               => array(),
			'recipients_home'          => '',
			'recipients_confirmed_by'  => 0,
			'recipients_confirmed_utc' => '',
			'schedule_ordinal'         => 'first',
			'schedule_weekday'         => 'monday',
			'schedule_time'            => '09:00',
			'schedule_timezone'        => 'Europe/London',
			'schedule_confirmed'       => false,
			'post_types'               => array( 'page', 'post' ),
			'scope_confirmed'          => false,
			'sitemap_discovery'        => false,
			'max_urls'                 => 2000,
			'gap_seconds'              => 1,
			'timeout'                  => 15,
			'max_bytes'                => 5242880,
			'retention_runs'           => 13,
			'approved_phones'          => array(),
			'approved_names'           => array(),
			'staging_patterns'         => array(),
			'notify_no_change'         => false,
			'remove_data_on_uninstall' => false,
		);
	}

	/**
	 * All settings, merged over defaults.
	 *
	 * @return array
	 */
	public static function all() {
		if ( null === self::$cache ) {
			$stored      = get_option( self::OPTION, array() );
			self::$cache = array_merge( self::defaults(), is_array( $stored ) ? $stored : array() );
		}
		return self::$cache;
	}

	/**
	 * One setting.
	 *
	 * @param string $key Key.
	 * @return mixed
	 */
	public static function get( $key ) {
		$all = self::all();
		return isset( $all[ $key ] ) ? $all[ $key ] : null;
	}

	/**
	 * Forget the request cache (tests, and after an update).
	 */
	public static function flush() {
		self::$cache = null;
	}

	/**
	 * Whether the wp-config constant is set. It stops scheduling, mail and
	 * manual audits (contract section 8).
	 *
	 * @return bool
	 */
	public static function constant_disabled() {
		return defined( 'MLTSA_DISABLE' ) && MLTSA_DISABLE;
	}

	/**
	 * Whether scheduling and mail are stopped, by the constant or the setting.
	 *
	 * @return bool
	 */
	public static function is_disabled() {
		return self::constant_disabled() || (bool) self::get( 'kill_switch' );
	}

	/**
	 * Why monitoring cannot be switched on, or an empty list if it can.
	 *
	 * @return array List of plain-text reasons.
	 */
	public static function monitoring_blockers() {
		$s   = self::all();
		$out = array();
		if ( empty( $s['scope_confirmed'] ) ) {
			$out[] = __( 'Confirm the audit scope.', 'mlt-schema-audit' );
		}
		if ( empty( $s['recipients'] ) ) {
			$out[] = __( 'Add at least one recipient.', 'mlt-schema-audit' );
		} elseif ( self::mail_paused() ) {
			$out[] = __( 'Reconfirm the recipients for this site address.', 'mlt-schema-audit' );
		}
		if ( empty( $s['schedule_confirmed'] ) ) {
			$out[] = __( 'Confirm the schedule.', 'mlt-schema-audit' );
		}
		return $out;
	}

	/**
	 * Clone and staging guard (M3): mail pauses when the home URL is not the
	 * one the recipients were confirmed on.
	 *
	 * @return bool
	 */
	public static function mail_paused() {
		$confirmed = (string) self::get( 'recipients_home' );
		return '' === $confirmed || self::normalise_home( $confirmed ) !== self::normalise_home( home_url( '/' ) );
	}

	/**
	 * Home URL compared without scheme case or trailing slash.
	 *
	 * @param string $url URL.
	 * @return string
	 */
	public static function normalise_home( $url ) {
		return rtrim( strtolower( (string) $url ), '/' );
	}

	/**
	 * Sanitise and save a set of changes, logging each changed group.
	 *
	 * @param array $changes Raw values (already unslashed).
	 * @param int   $user_id Acting user.
	 * @return array { saved: bool, errors: list }
	 */
	public static function update( array $changes, $user_id ) {
		$before = self::all();
		$after  = $before;
		$errors = array();

		foreach ( $changes as $key => $value ) {
			if ( ! array_key_exists( $key, $before ) ) {
				continue;
			}
			$clean = self::sanitise( $key, $value, $errors );
			if ( null !== $clean ) {
				$after[ $key ] = $clean;
			}
		}

		$recipients_changed = $after['recipients'] !== $before['recipients'];
		if ( $recipients_changed ) {
			// Any recipient change is a confirmation on the current address.
			$after['recipients_home']          = empty( $after['recipients'] ) ? '' : home_url( '/' );
			$after['recipients_confirmed_by']  = (int) $user_id;
			$after['recipients_confirmed_utc'] = gmdate( 'Y-m-d H:i:s' );
		}
		$schedule_keys = array( 'schedule_ordinal', 'schedule_weekday', 'schedule_time', 'schedule_timezone' );
		foreach ( $schedule_keys as $key ) {
			if ( $after[ $key ] !== $before[ $key ] && ! array_key_exists( 'schedule_confirmed', $changes ) ) {
				$after['schedule_confirmed'] = false;
			}
		}
		if ( $after['post_types'] !== $before['post_types'] && ! array_key_exists( 'scope_confirmed', $changes ) ) {
			$after['scope_confirmed'] = false;
		}

		if ( ! empty( $after['monitoring'] ) && empty( $before['monitoring'] ) ) {
			self::$cache = $after;
			$blockers    = self::monitoring_blockers();
			self::$cache = null;
			if ( ! empty( $blockers ) ) {
				$after['monitoring'] = false;
				$errors              = array_merge( $errors, $blockers );
			}
		}

		if ( $after === $before ) {
			return array(
				'saved'  => false,
				'errors' => $errors,
			);
		}

		update_option( self::OPTION, $after, false );
		self::flush();

		$repo = new Repository();
		if ( $recipients_changed ) {
			$repo->log_event(
				'recipients_changed',
				array(
					'count_before' => count( $before['recipients'] ),
					'count_after'  => count( $after['recipients'] ),
					'home'         => $after['recipients_home'],
				),
				$user_id
			);
			Ops\Outbox::rebuild_pending( $user_id );
		}
		$changed = array();
		foreach ( $after as $key => $value ) {
			if ( 'recipients' !== $key && 0 !== strpos( $key, 'recipients_' ) && $value !== $before[ $key ] ) {
				$changed[ $key ] = self::loggable( $key, $value );
			}
		}
		if ( ! empty( $changed ) ) {
			$event = isset( $changed['kill_switch'] ) ? 'kill_switch_changed' : 'settings_changed';
			$repo->log_event( $event, $changed, $user_id );
		}
		Ops\Scheduler::sync();

		return array(
			'saved'  => true,
			'errors' => $errors,
		);
	}

	/**
	 * Value as written to the event log: lists of personal data are counted,
	 * not copied (D2).
	 *
	 * @param string $key   Key.
	 * @param mixed  $value Value.
	 * @return mixed
	 */
	private static function loggable( $key, $value ) {
		if ( in_array( $key, array( 'approved_phones', 'approved_names' ), true ) ) {
			return count( (array) $value ) . ' entries';
		}
		return $value;
	}

	/**
	 * Sanitise one setting.
	 *
	 * @param string $key    Key.
	 * @param mixed  $value  Raw value.
	 * @param array  $errors Collected error messages.
	 * @return mixed|null Null to keep the old value.
	 */
	public static function sanitise( $key, $value, array &$errors ) {
		$bools = array( 'monitoring', 'kill_switch', 'schedule_confirmed', 'scope_confirmed', 'sitemap_discovery', 'notify_no_change', 'remove_data_on_uninstall' );
		if ( in_array( $key, $bools, true ) ) {
			return (bool) $value;
		}
		switch ( $key ) {
			case 'recipients':
				return self::sanitise_recipients( $value, $errors );
			case 'schedule_ordinal':
				return in_array( $value, self::ORDINALS, true ) ? $value : null;
			case 'schedule_weekday':
				return in_array( $value, self::WEEKDAYS, true ) ? $value : null;
			case 'schedule_time':
				if ( is_string( $value ) && preg_match( '/^([01]\d|2[0-3]):[0-5]\d$/', $value ) ) {
					return $value;
				}
				$errors[] = __( 'The time must be in 24-hour HH:MM form.', 'mlt-schema-audit' );
				return null;
			case 'schedule_timezone':
				if ( is_string( $value ) && in_array( $value, timezone_identifiers_list(), true ) ) {
					return $value;
				}
				$errors[] = __( 'Choose a timezone from the list.', 'mlt-schema-audit' );
				return null;
			case 'post_types':
				$allowed = get_post_types( array( 'public' => true ) );
				unset( $allowed['attachment'] );
				$out = array();
				foreach ( (array) $value as $type ) {
					if ( is_string( $type ) && isset( $allowed[ $type ] ) ) {
						$out[] = $type;
					}
				}
				sort( $out );
				return $out;
			case 'max_urls':
				return max( 1, min( 5000, (int) $value ) );
			case 'gap_seconds':
				return max( 0, min( 30, (int) $value ) );
			case 'timeout':
				return max( 5, min( 60, (int) $value ) );
			case 'max_bytes':
				return max( 262144, min( 20971520, (int) $value ) );
			case 'retention_runs':
				return max( 13, min( 120, (int) $value ) );
			case 'approved_phones':
				$out = array();
				foreach ( self::lines( $value ) as $line ) {
					$nsn = PageFacts::phone_nsn( $line );
					if ( '' !== $nsn ) {
						$out[] = $nsn;
					}
				}
				return array_values( array_unique( $out ) );
			case 'approved_names':
				return array_values( array_unique( array_map( 'sanitize_text_field', self::lines( $value ) ) ) );
			case 'staging_patterns':
				$out = array();
				foreach ( self::lines( $value ) as $line ) {
					$host = strtolower( preg_replace( '/[^a-z0-9.\-]/i', '', $line ) );
					if ( '' !== $host ) {
						$out[] = $host;
					}
				}
				return array_values( array_unique( $out ) );
		}
		return null;
	}

	/**
	 * Recipient list: valid addresses only, de-duplicated, capped.
	 *
	 * @param mixed $value  Text (one per line or comma separated) or list.
	 * @param array $errors Errors.
	 * @return array|null
	 */
	private static function sanitise_recipients( $value, array &$errors ) {
		$out = array();
		foreach ( self::lines( $value, true ) as $line ) {
			$email = sanitize_email( $line );
			if ( '' === $email || ! is_email( $email ) ) {
				/* translators: %s: the rejected text, escaped on output. */
				$errors[] = sprintf( __( 'Not a valid email address: %s', 'mlt-schema-audit' ), $line );
				return null;
			}
			$out[ strtolower( $email ) ] = strtolower( $email );
		}
		if ( count( $out ) > self::MAX_RECIPIENTS ) {
			/* translators: %d: maximum number of recipients. */
			$errors[] = sprintf( __( 'No more than %d recipients.', 'mlt-schema-audit' ), self::MAX_RECIPIENTS );
			return null;
		}
		$out = array_values( $out );
		sort( $out );
		return $out;
	}

	/**
	 * Split text into trimmed non-empty lines.
	 *
	 * @param mixed $value  Text or list.
	 * @param bool  $commas Also split on commas and semicolons.
	 * @return array
	 */
	public static function lines( $value, $commas = false ) {
		if ( is_array( $value ) ) {
			$value = implode( "\n", array_map( 'strval', $value ) );
		}
		$parts = preg_split( $commas ? '/[\r\n,;]+/' : '/[\r\n]+/', (string) $value );
		return array_values( array_filter( array_map( 'trim', $parts ), 'strlen' ) );
	}
}
