<?php
/**
 * Issue identity, the issue register's state changes, and run-to-run
 * comparison. Pure functions; the repository applies the results.
 *
 * Contract section 6: only the scanner sets verification state; a timeout,
 * an excluded URL, a removed or changed rule or a reduced scope never sets
 * "no longer detected"; a removed or redirected page gets its own state; a
 * new or changed rule is labelled as a rule change, not a website change.
 * A site-wide issue is cleared only when every page and resource it rested
 * on was read again; a full-scope run alone is not enough.
 *
 * @package MLT\SchemaAudit
 */

namespace MLT\SchemaAudit\Engine;

defined( 'ABSPATH' ) || defined( 'MLTSA_TESTING' ) || exit;

/**
 * Comparator.
 */
class Comparator {

	/**
	 * Verification states that mean "currently observed".
	 */
	const ACTIVE_STATES = array( 'present', 'changed', 'returned', 'unavailable' );

	/**
	 * Page coverage outcomes that mean the page was read and evaluated.
	 */
	const EVALUATED = array( 'ok' );

	/**
	 * Page coverage outcomes that mean the page has gone.
	 */
	const REMOVED = array( 'not_found', 'gone', 'redirected' );

	/**
	 * Page coverage outcomes that mean we could not tell.
	 */
	const UNKNOWN = array( 'timeout', 'error', 'unavailable', 'blocked', 'too_large', 'http_error', 'redirect_limit', 'pending' );

	/**
	 * Audits in a row an issue must be held as unavailable before the
	 * coverage figure counts it as repeatedly unchecked.
	 */
	const REPEAT_UNAVAILABLE = 2;

	/**
	 * Stable identity for an issue: site-wide issues by rule, entity and
	 * property; page issues also by page path. @graph positions are removed
	 * from the JSON path so reordering nodes does not create a new issue.
	 *
	 * @param string $page_url Page URL ('' for site-wide).
	 * @param array  $finding  Finding.
	 * @return string
	 */
	public static function issue_key( $page_url, array $finding ) {
		$path = (string) preg_replace( "/\\['@graph'\\]\\[\\d+\\]/", '', (string) $finding['path'] );
		if ( ! empty( $finding['site_wide'] ) ) {
			$parts = array( 'site', $finding['rule_id'], $finding['entity'], $finding['property'] );
		} else {
			$parts = array( Evaluator::url_key( $page_url ), $finding['rule_id'], $finding['entity'], $finding['property'], $path );
		}
		return sha1( implode( "\x1f", $parts ) );
	}

	/**
	 * Hash of what was observed, for "changed" detection.
	 *
	 * @param array $finding Finding.
	 * @return string
	 */
	public static function observed_hash( array $finding ) {
		return sha1( (string) $finding['observed'] . "\x1f" . (string) $finding['comparison'] );
	}

	/**
	 * Work out the issue register changes for a finished run.
	 *
	 * @param array  $issues       issue_key => issue row (id, page_url, rule_id, rule_version,
	 *                             verification_state, work_status, observed_hash, site_wide).
	 * @param array  $findings     issue_key => finding (with page_url, observed_hash).
	 * @param array  $pages        url_key => coverage outcome for pages in this run's scope.
	 * @param array  $fingerprint  rule_id => version for this run.
	 * @param array  $prior_fingerprint rule_id => version of the previous comparable run, or empty.
	 * @param bool   $full_scope   Whether this run covered the full scope (site-wide rules ran).
	 * @param array  $resources    Resource URL => check outcome, for every resource a page read in this run references.
	 * @return array { insert: issue_key => fields, update: issue_key => fields, events: list,
	 *                 unavailable: issue keys held as unavailable in this run, summary }
	 */
	public static function reconcile( array $issues, array $findings, array $pages, array $fingerprint, array $prior_fingerprint, $full_scope, array $resources = array() ) {
		$out = array(
			'insert'      => array(),
			'update'      => array(),
			'events'      => array(),
			'unavailable' => array(),
			'summary'     => array(
				'new'                => 0,
				'new_rule_change'    => 0,
				'returned'           => 0,
				'changed'            => 0,
				'still_present'      => 0,
				'no_longer_detected' => 0,
				'page_removed'       => 0,
				'unavailable'        => 0,
				'rule_change_held'   => 0,
			),
		);

		foreach ( $findings as $key => $finding ) {
			if ( ! isset( $issues[ $key ] ) ) {
				if ( empty( $prior_fingerprint ) ) {
					$reason = 'baseline';
				} elseif ( isset( $prior_fingerprint[ $finding['rule_id'] ] ) && (int) $prior_fingerprint[ $finding['rule_id'] ] === (int) $finding['rule_version'] ) {
					$reason = 'site_change';
				} else {
					$reason = 'rule_change';
					++$out['summary']['new_rule_change'];
				}
				$out['insert'][ $key ] = array(
					'verification_state' => 'present',
					'work_status'        => 'open',
					'change_reason'      => $reason,
					'observed_hash'      => $finding['observed_hash'],
				);
				++$out['summary']['new'];
				continue;
			}

			$issue  = $issues[ $key ];
			$update = array(
				'observed_hash' => $finding['observed_hash'],
				'rule_version'  => (int) $finding['rule_version'],
			);
			if ( in_array( $issue['verification_state'], array( 'no_longer_detected', 'page_removed' ), true ) ) {
				$update['verification_state'] = 'returned';
				$update['change_reason']      = 'site_change';
				++$out['summary']['returned'];
				if ( 'resolved' === $issue['work_status'] ) {
					$update['work_status'] = 'open';
					$out['events'][]       = array( $key, 'reopened', 'Detected again after it was resolved.' );
				}
			} elseif ( $issue['observed_hash'] !== $finding['observed_hash'] ) {
				$update['verification_state'] = 'changed';
				$update['change_reason']      = (int) $issue['rule_version'] === (int) $finding['rule_version'] ? 'site_change' : 'rule_change';
				++$out['summary']['changed'];
				if ( in_array( $issue['work_status'], array( 'accepted_exception', 'false_positive' ), true ) ) {
					$update['work_status'] = 'open';
					$out['events'][]       = array( $key, 'reopened', 'The evidence behind this exception changed, so it needs review again.' );
				}
			} else {
				$update['verification_state'] = 'present';
				++$out['summary']['still_present'];
			}
			$out['update'][ $key ] = $update;
		}

		foreach ( $issues as $key => $issue ) {
			if ( isset( $findings[ $key ] ) || ! in_array( $issue['verification_state'], self::ACTIVE_STATES, true ) ) {
				continue;
			}
			$rule_same = isset( $fingerprint[ $issue['rule_id'] ] ) && (int) $fingerprint[ $issue['rule_id'] ] === (int) $issue['rule_version'];

			if ( ! empty( $issue['site_wide'] ) ) {
				if ( ! $full_scope ) {
					continue;
				}
				$evidence = self::evidence_state( self::refs( $issue, $pages ), $pages, $resources );
				if ( 'unknown' === $evidence ) {
					if ( 'unavailable' !== $issue['verification_state'] ) {
						$out['update'][ $key ] = array( 'verification_state' => 'unavailable' );
					}
					++$out['summary']['unavailable'];
					$out['unavailable'][] = $key;
					continue;
				}
				if ( 'missing' === $evidence ) {
					continue; // Evidence outside this run's scope: untouched.
				}
				if ( ! $rule_same ) {
					++$out['summary']['rule_change_held'];
					continue;
				}
				$out['update'][ $key ] = array( 'verification_state' => 'no_longer_detected' );
				++$out['summary']['no_longer_detected'];
				continue;
			}

			$page = Evaluator::url_key( $issue['page_url'] );
			if ( ! isset( $pages[ $page ] ) ) {
				continue; // Not in this run's scope: untouched.
			}
			$coverage = $pages[ $page ];
			if ( in_array( $coverage, self::EVALUATED, true ) ) {
				if ( ! $rule_same ) {
					++$out['summary']['rule_change_held'];
					continue;
				}
				$out['update'][ $key ] = array( 'verification_state' => 'no_longer_detected' );
				++$out['summary']['no_longer_detected'];
			} elseif ( in_array( $coverage, self::REMOVED, true ) ) {
				$out['update'][ $key ] = array( 'verification_state' => 'page_removed' );
				++$out['summary']['page_removed'];
			} elseif ( in_array( $coverage, self::UNKNOWN, true ) ) {
				if ( 'unavailable' !== $issue['verification_state'] ) {
					$out['update'][ $key ] = array( 'verification_state' => 'unavailable' );
				}
				++$out['summary']['unavailable'];
				$out['unavailable'][] = $key;
			}
		}
		return $out;
	}

	/**
	 * How many audits in a row each issue has been held as unavailable.
	 * Read-only bookkeeping for the coverage figure: it never changes an
	 * issue's state.
	 *
	 * @param array $previous    Issue ID => audits in a row, from the last finished run.
	 * @param array $unavailable Issue IDs held as unavailable in this run.
	 * @param array $still       Issue IDs still unavailable but outside this run's scope (carried over).
	 * @return array Issue ID => audits in a row.
	 */
	public static function unavailable_streaks( array $previous, array $unavailable, array $still ) {
		$out = array();
		foreach ( $unavailable as $id ) {
			$id         = (int) $id;
			$out[ $id ] = ( isset( $previous[ $id ] ) ? (int) $previous[ $id ] : 0 ) + 1;
		}
		foreach ( $still as $id ) {
			$id = (int) $id;
			if ( ! isset( $out[ $id ] ) && isset( $previous[ $id ] ) ) {
				$out[ $id ] = (int) $previous[ $id ];
			}
		}
		ksort( $out );
		return $out;
	}

	/**
	 * The coverage figure: issues held as unavailable in this run for at
	 * least REPEAT_UNAVAILABLE audits in a row, longest first.
	 *
	 * @param array $streaks     Issue ID => audits in a row.
	 * @param array $unavailable Issue IDs held as unavailable in this run.
	 * @return array { min_runs, issues, longest, ids (at most 50) }
	 */
	public static function repeat_unavailable( array $streaks, array $unavailable ) {
		$hits = array();
		foreach ( $unavailable as $id ) {
			$id = (int) $id;
			if ( isset( $streaks[ $id ] ) && $streaks[ $id ] >= self::REPEAT_UNAVAILABLE ) {
				$hits[ $id ] = (int) $streaks[ $id ];
			}
		}
		uksort(
			$hits,
			static function ( $a, $b ) use ( $hits ) {
				return $hits[ $b ] === $hits[ $a ] ? $a - $b : $hits[ $b ] - $hits[ $a ];
			}
		);
		return array(
			'min_runs' => self::REPEAT_UNAVAILABLE,
			'issues'   => count( $hits ),
			'longest'  => empty( $hits ) ? 0 : max( $hits ),
			'ids'      => array_slice( array_keys( $hits ), 0, 50 ),
		);
	}

	/**
	 * The evidence refs stored for a site-wide issue. An issue stored before
	 * evidence was recorded falls back to every page in this run's scope
	 * (and its resource, for URL-004), so it clears only on full coverage.
	 *
	 * @param array $issue Issue row (evidence, entity_key).
	 * @param array $pages url_key => coverage for this run.
	 * @return array
	 */
	public static function refs( array $issue, array $pages ) {
		$refs = isset( $issue['evidence'] ) ? json_decode( (string) $issue['evidence'], true ) : null;
		if ( is_array( $refs ) && ! empty( $refs ) ) {
			return array_values( array_map( 'strval', $refs ) );
		}
		$refs   = array_map( 'strval', array_keys( $pages ) );
		$entity = isset( $issue['entity_key'] ) ? (string) $issue['entity_key'] : '';
		if ( 0 === strpos( $entity, 'resource:' ) ) {
			$refs[] = $entity;
		}
		return $refs;
	}

	/**
	 * Whether the evidence behind a site-wide issue was read in this run.
	 *
	 * "read": every page was read or has conclusively gone, and every
	 * resource was checked or is no longer referenced by any page read.
	 * "unknown": a page or resource could not be read (timeout, error,
	 * pending, over the resource cap). "missing": a page is outside this
	 * run (excluded, or dropped from the scope), or there is no evidence.
	 *
	 * @param array $refs      Page url_keys and resource:<url> refs.
	 * @param array $pages     url_key => coverage for this run.
	 * @param array $resources Resource URL => check outcome, for every resource a page read in this run references.
	 * @return string read|unknown|missing
	 */
	public static function evidence_state( array $refs, array $pages, array $resources ) {
		$settled = array_merge( self::EVALUATED, self::REMOVED );
		$read    = 0;
		$held    = 0;
		foreach ( $refs as $ref ) {
			$ref = (string) $ref;
			if ( 0 === strpos( $ref, 'resource:' ) ) {
				$url = substr( $ref, strlen( 'resource:' ) );
				if ( isset( $resources[ $url ] ) && ! in_array( $resources[ $url ], $settled, true ) ) {
					return 'unknown';
				}
				continue; // Checked, or no page read in this run references it.
			}
			$coverage = isset( $pages[ $ref ] ) ? $pages[ $ref ] : '';
			if ( in_array( $coverage, self::UNKNOWN, true ) ) {
				return 'unknown';
			}
			if ( in_array( $coverage, $settled, true ) ) {
				++$read;
			} else {
				++$held;
			}
		}
		// Every finding rests on at least one page, so no page ref means no evidence.
		return ( $read > 0 && 0 === $held ) ? 'read' : 'missing';
	}

	/**
	 * Compare a run with its baseline for the change log and digest.
	 *
	 * Formatting-only changes (whitespace, key order) do not count, because
	 * markup is compared by canonical hash.
	 *
	 * @param array $baseline { findings: key => { hash, rule_id, page, refs (site-wide) }, pages: url_key => { coverage, markup } , fingerprint }.
	 * @param array $current  Same shape, plus resources: resource URL => check outcome.
	 * @param array $ever     Issue keys seen in any run before the baseline.
	 * @return array
	 */
	public static function compare( array $baseline, array $current, array $ever = array() ) {
		$result = array(
			'new'                 => array(),
			'new_rule_change'     => array(),
			'returned'            => array(),
			'resolved'            => array(),
			'held_rule_change'    => array(),
			'changed'             => array(),
			'changed_rule_change' => array(),
			'unchanged'           => array(),
			'pages_added'         => array(),
			'pages_removed'       => array(),
			'markup_changed'      => array(),
			'coverage_lost'       => array(),
			'rules_changed'       => array(),
		);
		// A rule counts as changed when it was added, removed or re-versioned,
		// so look at the union of both runs' rule IDs, not only the current set.
		$rule_ids = array_unique( array_merge( array_keys( $baseline['fingerprint'] ), array_keys( $current['fingerprint'] ) ) );
		foreach ( $rule_ids as $rule ) {
			if ( ! isset( $baseline['fingerprint'][ $rule ], $current['fingerprint'][ $rule ] ) || (int) $baseline['fingerprint'][ $rule ] !== (int) $current['fingerprint'][ $rule ] ) {
				$result['rules_changed'][] = (string) $rule;
			}
		}
		foreach ( $current['findings'] as $key => $item ) {
			if ( ! isset( $baseline['findings'][ $key ] ) ) {
				if ( in_array( $item['rule_id'], $result['rules_changed'], true ) ) {
					$result['new_rule_change'][] = $key;
				} elseif ( isset( $ever[ $key ] ) ) {
					$result['returned'][] = $key;
				} else {
					$result['new'][] = $key;
				}
			} elseif ( $baseline['findings'][ $key ]['hash'] !== $item['hash'] ) {
				if ( in_array( $item['rule_id'], $result['rules_changed'], true ) ) {
					$result['changed_rule_change'][] = $key;
				} else {
					$result['changed'][] = $key;
				}
			} else {
				$result['unchanged'][] = $key;
			}
		}
		$coverage  = array();
		$resources = isset( $current['resources'] ) ? (array) $current['resources'] : array();
		foreach ( $current['pages'] as $page => $info ) {
			$coverage[ $page ] = $info['coverage'];
		}
		foreach ( $baseline['findings'] as $key => $item ) {
			if ( isset( $current['findings'][ $key ] ) ) {
				continue;
			}
			$page = isset( $item['page'] ) ? $item['page'] : '';
			// Only a page read in both runs, under the same rule version, can
			// show an issue as resolved; a site-wide issue needs all of its
			// evidence read.
			if ( '' === $page ) {
				$read = 'read' === self::evidence_state( isset( $item['refs'] ) ? (array) $item['refs'] : array(), $coverage, $resources );
			} else {
				$read = isset( $current['pages'][ $page ] ) && 'ok' === $current['pages'][ $page ]['coverage'];
			}
			if ( ! $read ) {
				continue;
			}
			// A removed or changed rule is not a website fix: the issue is held.
			if ( in_array( $item['rule_id'], $result['rules_changed'], true ) ) {
				$result['held_rule_change'][] = $key;
			} else {
				$result['resolved'][] = $key;
			}
		}
		foreach ( $current['pages'] as $page => $info ) {
			if ( ! isset( $baseline['pages'][ $page ] ) ) {
				$result['pages_added'][] = $page;
				continue;
			}
			$before = $baseline['pages'][ $page ];
			if ( 'ok' === $before['coverage'] && 'ok' !== $info['coverage'] ) {
				$result['coverage_lost'][] = $page;
			}
			if ( 'ok' === $before['coverage'] && 'ok' === $info['coverage'] && (string) $before['markup'] !== (string) $info['markup'] ) {
				$result['markup_changed'][] = $page;
			}
		}
		foreach ( $baseline['pages'] as $page => $info ) {
			if ( ! isset( $current['pages'][ $page ] ) ) {
				$result['pages_removed'][] = $page;
			}
		}
		return $result;
	}

	/**
	 * Whether a comparison holds anything worth an email.
	 *
	 * @param array $comparison Output of compare().
	 * @return bool
	 */
	public static function is_meaningful( array $comparison ) {
		foreach ( array( 'new', 'new_rule_change', 'returned', 'resolved', 'held_rule_change', 'changed', 'changed_rule_change', 'pages_added', 'pages_removed', 'markup_changed', 'coverage_lost' ) as $list ) {
			if ( ! empty( $comparison[ $list ] ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Canonical markup hash for a page: hash of the sorted canonical hashes
	 * of its blocks (parsed or not), so block reordering alone is ignored.
	 *
	 * @param array $blocks Extracted blocks.
	 * @return string
	 */
	public static function markup_hash( array $blocks ) {
		$hashes = array();
		foreach ( $blocks as $block ) {
			$hashes[] = '' !== $block['canonical_hash'] ? $block['canonical_hash'] : $block['hash'];
		}
		sort( $hashes );
		return sha1( implode( ',', $hashes ) );
	}
}
