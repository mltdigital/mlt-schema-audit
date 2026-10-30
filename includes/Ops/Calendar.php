<?php
/**
 * Monthly calendar maths (contract section 8): the first, second, third,
 * fourth or last weekday of the month at a local time in an explicit
 * timezone. Pure PHP, so it is unit tested without WordPress.
 *
 * @package MLT\SchemaAudit
 */

namespace MLT\SchemaAudit\Ops;

defined( 'ABSPATH' ) || defined( 'MLTSA_TESTING' ) || exit;

/**
 * Calendar.
 */
class Calendar {

	/**
	 * The occurrence in a given month.
	 *
	 * @param int    $year     Year.
	 * @param int    $month    Month 1 to 12.
	 * @param string $ordinal  first, second, third, fourth or last.
	 * @param string $weekday  monday to sunday.
	 * @param string $time     HH:MM local time.
	 * @param string $timezone Timezone identifier.
	 * @return int UTC timestamp.
	 */
	public static function occurrence( $year, $month, $ordinal, $weekday, $time, $timezone ) {
		$tz            = new \DateTimeZone( $timezone );
		$base          = new \DateTimeImmutable( sprintf( '%04d-%02d-01 00:00:00', $year, $month ), $tz );
		$day           = $base->modify( $ordinal . ' ' . $weekday . ' of this month' );
		list( $h, $m ) = array_map( 'intval', explode( ':', $time ) );
		// setTime on a local date handles the clock change: a time that does
		// not exist on that day moves forward, as PHP defines.
		return $day->setTime( $h, $m )->getTimestamp();
	}

	/**
	 * Next occurrences strictly after a moment.
	 *
	 * @param array $s     Settings (schedule_ordinal, schedule_weekday, schedule_time, schedule_timezone).
	 * @param int   $after UTC timestamp.
	 * @param int   $count How many.
	 * @return array UTC timestamps.
	 */
	public static function next( array $s, $after, $count = 1 ) {
		$tz     = new \DateTimeZone( $s['schedule_timezone'] );
		$cursor = ( new \DateTimeImmutable( '@' . (int) $after ) )->setTimezone( $tz );
		$year   = (int) $cursor->format( 'Y' );
		$month  = (int) $cursor->format( 'n' );
		$out    = array();
		for ( $i = 0; $i < 24; $i++ ) {
			if ( count( $out ) >= $count ) {
				break;
			}
			$ts = self::occurrence( $year, $month, $s['schedule_ordinal'], $s['schedule_weekday'], $s['schedule_time'], $s['schedule_timezone'] );
			if ( $ts > $after ) {
				$out[] = $ts;
			}
			++$month;
			if ( $month > 12 ) {
				$month = 1;
				++$year;
			}
		}
		return $out;
	}

	/**
	 * The most recent occurrence at or before a moment.
	 *
	 * @param array $s   Settings.
	 * @param int   $now UTC timestamp.
	 * @return int UTC timestamp.
	 */
	public static function previous( array $s, $now ) {
		$tz     = new \DateTimeZone( $s['schedule_timezone'] );
		$cursor = ( new \DateTimeImmutable( '@' . (int) $now ) )->setTimezone( $tz );
		$year   = (int) $cursor->format( 'Y' );
		$month  = (int) $cursor->format( 'n' );
		for ( $i = 0; $i < 3; $i++ ) {
			$ts = self::occurrence( $year, $month, $s['schedule_ordinal'], $s['schedule_weekday'], $s['schedule_time'], $s['schedule_timezone'] );
			if ( $ts <= $now ) {
				return $ts;
			}
			--$month;
			if ( $month < 1 ) {
				$month = 12;
				--$year;
			}
		}
		return 0;
	}

	/**
	 * Stable key for one scheduled occurrence, so a second start for the same
	 * month is refused by the unique index (S2).
	 *
	 * @param int    $occurrence UTC timestamp of the occurrence.
	 * @param string $timezone   Timezone.
	 * @return string
	 */
	public static function schedule_key( $occurrence, $timezone ) {
		$local = ( new \DateTimeImmutable( '@' . (int) $occurrence ) )->setTimezone( new \DateTimeZone( $timezone ) );
		return 'monthly-' . $local->format( 'Y-m' );
	}
}
