<?php
/**
 * The resumable audit worker.
 *
 * A run moves through phases: discover, fetch, site, resources, reconcile,
 * notify, done. Each tick takes the run's lock, works until its time budget
 * is spent, and releases the lock. Every URL is written once, so a tick that
 * dies part-way resumes at the next pending URL (S2, M6). Requests are made
 * one at a time with a gap, backing off when the site is slow (F3, S1).
 *
 * @package MLT\SchemaAudit
 */

namespace MLT\SchemaAudit\Ops;

use MLT\SchemaAudit\Discovery;
use MLT\SchemaAudit\Engine\Comparator;
use MLT\SchemaAudit\Engine\Evaluator;
use MLT\SchemaAudit\Engine\Extractor;
use MLT\SchemaAudit\Engine\Fetcher;
use MLT\SchemaAudit\Engine\HttpClient;
use MLT\SchemaAudit\Engine\SiteRules;
use MLT\SchemaAudit\Engine\UrlPolicy;
use MLT\SchemaAudit\Engine\WpHttpClient;
use MLT\SchemaAudit\Settings;
use MLT\SchemaAudit\Store\Repository;

defined( 'ABSPATH' ) || exit;

/**
 * Worker.
 */
class Worker {

	/**
	 * Attempts at one URL before it is recorded as an error. An attempt that
	 * never finished (the process died) counts.
	 */
	const MAX_URL_ATTEMPTS = 3;

	/**
	 * Responses slower than this make the worker wait longer (milliseconds).
	 */
	const SLOW_MS = 3000;

	/**
	 * Repository.
	 *
	 * @var Repository
	 */
	private $repo;

	/**
	 * Settings.
	 *
	 * @var array
	 */
	private $settings;

	/**
	 * Transport, injectable for tests.
	 *
	 * @var HttpClient
	 */
	private $client;

	/**
	 * Sleep callable, injectable for tests.
	 *
	 * @var callable
	 */
	private $sleep;

	/**
	 * Requests made by this worker (tests and S4).
	 *
	 * @var int
	 */
	public $requests = 0;

	/**
	 * Constructor.
	 *
	 * @param HttpClient|null $client Transport.
	 * @param callable|null   $sleep  Sleep function.
	 */
	public function __construct( $client = null, $sleep = null ) {
		$this->repo     = new Repository();
		$this->settings = Settings::all();
		$this->client   = $client instanceof HttpClient ? $client : new WpHttpClient();
		$this->sleep    = is_callable( $sleep ) ? $sleep : 'sleep';
	}

	/**
	 * One scheduler tick: catch-up check, the active run, then the outbox.
	 *
	 * @param int $budget Seconds.
	 * @return array Status.
	 */
	public static function tick( $budget ) {
		update_option( 'mltsa_last_tick', time(), false );
		if ( Settings::constant_disabled() ) {
			return array( 'state' => 'disabled' );
		}
		Scheduler::catch_up();
		$status = array( 'state' => 'idle' );
		$repo   = new Repository();
		$run    = $repo->active_run();
		if ( $run ) {
			$worker = new self();
			$status = $worker->process( (int) $run['id'], $budget );
		}
		Outbox::process();
		if ( $repo->active_run() ) {
			Scheduler::kick_worker( 30 );
		}
		return $status;
	}

	/**
	 * Work on a run for up to $budget seconds.
	 *
	 * @param int $run_id Run ID.
	 * @param int $budget Seconds.
	 * @return array { state, phase, done, total, run_id }
	 */
	public function process( $run_id, $budget ) {
		$deadline = microtime( true ) + max( 1, (int) $budget );
		$token    = wp_generate_password( 20, false );
		if ( ! $this->repo->claim_run( $run_id, $token, (int) $budget + 120 ) ) {
			return $this->status( $run_id, 'locked' );
		}
		try {
			$run = $this->repo->get_run( $run_id );
			if ( $run && 'queued' === $run['state'] ) {
				$this->repo->update_run(
					$run_id,
					array(
						'state'       => 'running',
						'started_utc' => Repository::now(),
					)
				);
				$run = $this->repo->get_run( $run_id );
			}
			while ( $run && 'running' === $run['state'] && microtime( true ) < $deadline ) {
				if ( $this->should_stop( $run ) ) {
					$this->finish( $run, 'cancelled', array( 'cancelled_reason' => 'kill_switch' ) );
					break;
				}
				$more = $this->step( $run, $deadline );
				$run  = $this->repo->get_run( $run_id );
				if ( ! $more ) {
					break;
				}
			}
		} finally {
			$this->repo->release_run( $run_id, $token );
		}
		return $this->status( $run_id, 'worked' );
	}

	/**
	 * Whether the kill switch stops this run now (S4). The constant stops
	 * every run; the setting stops monthly runs, not manual ones.
	 *
	 * @param array $run Run.
	 * @return bool
	 */
	private function should_stop( array $run ) {
		if ( Settings::constant_disabled() ) {
			return true;
		}
		wp_cache_delete( Settings::OPTION, 'options' );
		Settings::flush();
		return 'monthly' === $run['run_type'] && (bool) Settings::get( 'kill_switch' );
	}

	/**
	 * Do one unit of work in the run's current phase.
	 *
	 * @param array $run      Run.
	 * @param float $deadline Deadline.
	 * @return bool Whether to keep going in this tick.
	 */
	private function step( array $run, $deadline ) {
		switch ( $run['phase'] ) {
			case 'discover':
				$this->discover( $run );
				return true;
			case 'fetch':
				return $this->fetch_batch( $run, $deadline );
			case 'site':
				$this->site_rules( $run );
				return true;
			case 'resources':
				return $this->check_resources( $run, $deadline );
			case 'reconcile':
				$this->reconcile( $run );
				return true;
			case 'notify':
				$this->notify( $run );
				return false;
		}
		return false;
	}

	/**
	 * Engine objects for this site.
	 *
	 * @return array [ UrlPolicy, Fetcher ]
	 */
	private function engine() {
		$policy  = new UrlPolicy( home_url( '/' ), defined( 'MLTSA_ALLOW_PRIVATE_SELF' ) && MLTSA_ALLOW_PRIVATE_SELF );
		$fetcher = new Fetcher(
			$policy,
			$this->client,
			array(
				'timeout'    => (int) $this->settings['timeout'],
				'max_bytes'  => (int) $this->settings['max_bytes'],
				'user_agent' => self::user_agent(),
			),
			$this->sleep
		);
		return array( $policy, $fetcher );
	}

	/**
	 * Identifiable user agent (contract section 2, F8).
	 *
	 * @return string
	 */
	public static function user_agent() {
		return 'MLT-Schema-Audit/' . MLTSA_VERSION . ' (+' . home_url( '/' ) . ')';
	}

	/**
	 * Discover: freeze the URL list.
	 *
	 * @param array $run Run.
	 */
	private function discover( array $run ) {
		list( $policy, $fetcher ) = $this->engine();
		$scope                    = Repository::decode( $run['scope'] );
		if ( ! empty( $scope['urls'] ) ) {
			$candidates = array();
			foreach ( (array) $scope['urls'] as $url ) {
				$candidates[] = array(
					'url'     => (string) $url,
					'source'  => 'recheck',
					'post_id' => 0,
					'exclude' => '',
				);
			}
		} else {
			$candidates = Discovery::from_wordpress( $this->settings );
			if ( ! empty( $this->settings['sitemap_discovery'] ) ) {
				$candidates = array_merge( $candidates, Discovery::from_sitemaps( $fetcher, $policy ) );
				$this->requests += 1;
			}
		}
		$frozen = Discovery::freeze( $candidates, $policy, (int) $this->settings['max_urls'] );
		$seq    = 0;
		foreach ( $frozen['urls'] as $item ) {
			$this->repo->insert_run_url(
				array(
					'run_id'           => (int) $run['id'],
					'seq'              => ++$seq,
					'url'              => $item['url'],
					'url_key'          => $item['url_key'],
					'discovery_source' => substr( $item['source'], 0, 20 ),
					'post_id'          => $item['post_id'],
					'coverage'         => $item['coverage'],
					'coverage_reason'  => $item['reason'],
				)
			);
		}
		$scope['excluded_by_reason'] = $frozen['excluded_by_reason'];
		if ( empty( $scope['urls'] ) ) {
			$scope['status_exclusions'] = Discovery::status_exclusions( $this->settings );
		}
		$this->repo->update_run(
			(int) $run['id'],
			array(
				'phase'          => 'fetch',
				'url_count'      => (int) $frozen['included'],
				'excluded_count' => count( $frozen['urls'] ) - (int) $frozen['included'],
				'scope'          => (string) wp_json_encode( $scope ),
				'progress_utc'   => Repository::now(),
			)
		);
	}

	/**
	 * Fetch and evaluate pending URLs until the deadline.
	 *
	 * @param array $run      Run.
	 * @param float $deadline Deadline.
	 * @return bool
	 */
	private function fetch_batch( array $run, $deadline ) {
		list( $policy, $fetcher ) = $this->engine();
		$extractor                = new Extractor();
		$rows                     = $this->repo->pending_urls( (int) $run['id'], 20 );
		if ( empty( $rows ) ) {
			$this->repo->update_run( (int) $run['id'], array( 'phase' => 'site' ) );
			return true;
		}
		foreach ( $rows as $row ) {
			if ( microtime( true ) >= $deadline || $this->should_stop( $run ) ) {
				return false;
			}
			$attempts = (int) $row['attempts'] + 1;
			if ( $attempts > self::MAX_URL_ATTEMPTS ) {
				$this->repo->update_run_url(
					(int) $row['id'],
					array(
						'coverage'        => 'error',
						'coverage_reason' => 'worker_stopped',
					)
				);
				continue;
			}
			// Record the attempt before the request, so a request that kills
			// the process is not repeated for ever.
			$this->repo->update_run_url( (int) $row['id'], array( 'attempts' => $attempts ) );
			$result = $fetcher->fetch( $row['url'] );
			++$this->requests;
			$this->record_page( $run, $row, $result, $extractor, $policy );
			$this->repo->update_run(
				(int) $run['id'],
				array(
					'done_count'   => (int) $run['done_count'] + 1,
					'progress_utc' => Repository::now(),
				)
			);
			$run['done_count'] = (int) $run['done_count'] + 1;
			$this->pause( (int) $result['duration_ms'] );
		}
		return true;
	}

	/**
	 * Wait between requests, longer when the site is slow.
	 *
	 * @param int $duration_ms Last response time.
	 */
	private function pause( $duration_ms ) {
		$gap = (int) $this->settings['gap_seconds'];
		if ( $duration_ms > self::SLOW_MS ) {
			$gap = max( $gap, min( 10, (int) ceil( $duration_ms / 1000 ) ) );
		}
		if ( $gap > 0 ) {
			call_user_func( $this->sleep, $gap );
		}
	}

	/**
	 * Store one page's observation, blocks and rule outcomes.
	 *
	 * @param array      $run       Run.
	 * @param array      $row       Run URL row.
	 * @param array      $result    Fetch result.
	 * @param Extractor  $extractor Extractor.
	 * @param UrlPolicy  $policy    Policy.
	 */
	private function record_page( array $run, array $row, array $result, Extractor $extractor, UrlPolicy $policy ) {
		$coverage = $result['outcome'];
		$reason   = (string) $result['reason'];
		if ( 'ok' === $coverage && Evaluator::url_key( $result['final_url'] ) !== Evaluator::url_key( $row['url'] ) ) {
			$coverage = 'redirected';
		}
		if ( 'ok' === $coverage && '' !== $result['content_type'] && ! preg_match( '#^(text/html|application/xhtml\+xml)#i', $result['content_type'] ) ) {
			$coverage = 'not_html';
		}
		$fields = array(
			'final_url'      => substr( (string) $result['final_url'], 0, 2048 ),
			'redirect_chain' => (string) wp_json_encode( $result['chain'] ),
			'http_status'    => (int) $result['status'],
			'fetched_utc'    => Repository::now(),
			'duration_ms'    => (int) $result['duration_ms'],
			'response_hash'  => (string) $result['response_hash'],
			'coverage'       => $coverage,
			'coverage_reason' => substr( $reason, 0, 100 ),
		);
		if ( 'ok' !== $coverage ) {
			$this->repo->update_run_url( (int) $row['id'], $fields );
			return;
		}

		$extraction = $extractor->extract( $result['body'] );
		$evaluator  = new Evaluator(
			array(
				'page_url'         => $row['url'],
				'own_hosts'        => $policy->allowed_hosts(),
				'home_scheme'      => $policy->home_scheme(),
				'staging_patterns' => (array) $this->settings['staging_patterns'],
				'approved_phones'  => (array) $this->settings['approved_phones'],
				'approved_names'   => (array) $this->settings['approved_names'],
			)
		);
		$evaluation = $evaluator->evaluate( $extraction );

		foreach ( $extraction['blocks'] as $block ) {
			$this->repo->insert_block(
				array(
					'run_id'            => (int) $run['id'],
					'run_url_id'        => (int) $row['id'],
					'block_index'       => (int) $block['index'],
					'format'            => $block['format'],
					'raw'               => $block['raw'],
					'raw_length'        => (int) $block['raw_length'],
					'parse_state'       => $block['parse'],
					'parse_error'       => Evaluator::cap( $block['error'] ),
					'block_hash'        => $block['hash'],
					'canonical_hash'    => $block['canonical_hash'],
					'source'            => $block['source'],
					'source_confidence' => $block['source_confidence'],
				)
			);
		}
		foreach ( $evaluation['findings'] as $finding ) {
			$this->store_finding( (int) $run['id'], (int) $row['id'], $row['url'], $finding );
		}

		$fields['canonical']    = substr( (string) $extraction['canonical'], 0, 2048 );
		$fields['robots']       = substr( (string) $extraction['robots'], 0, 255 );
		$fields['title']        = Evaluator::cap( $extraction['title'] );
		$fields['markup_hash']  = Comparator::markup_hash( $extraction['blocks'] );
		$fields['jsonld_count'] = count( $extraction['blocks'] );
		$fields['microdata']    = min( 65535, (int) $extraction['microdata'] );
		$fields['rdfa']         = min( 65535, (int) $extraction['rdfa'] );
		$fields['facts']        = (string) wp_json_encode( $evaluation['site'] );
		$this->repo->update_run_url( (int) $row['id'], $fields );
	}

	/**
	 * Store a non-pass rule outcome as an occurrence.
	 *
	 * @param int    $run_id     Run ID.
	 * @param int    $run_url_id Run URL ID.
	 * @param string $page_url   Page URL.
	 * @param array  $finding    Finding.
	 */
	private function store_finding( $run_id, $run_url_id, $page_url, array $finding ) {
		if ( 'pass' === $finding['outcome'] ) {
			return;
		}
		$site_wide = ! empty( $finding['site_wide'] );
		$this->repo->insert_occurrence(
			array(
				'run_id'            => $run_id,
				'run_url_id'        => $run_url_id,
				'issue_key'         => Comparator::issue_key( $site_wide ? '' : $page_url, $finding ),
				'rule_id'           => $finding['rule_id'],
				'rule_version'      => (int) $finding['rule_version'],
				'outcome'           => $finding['outcome'],
				'severity'          => $finding['severity'],
				'confidence'        => $finding['confidence'],
				'entity_key'        => substr( (string) $finding['entity'], 0, 1024 ),
				'entity_type'       => substr( (string) $finding['entity_type'], 0, 255 ),
				'property'          => substr( (string) $finding['property'], 0, 100 ),
				'block_index'       => (int) $finding['block'],
				'json_path'         => substr( (string) $finding['path'], 0, 1024 ),
				'observed'          => (string) $finding['observed'],
				'comparison'        => (string) $finding['comparison'],
				'snippet'           => (string) $finding['snippet'],
				'observed_hash'     => Comparator::observed_hash( $finding ),
				'source'            => substr( (string) $finding['source'], 0, 60 ),
				'source_confidence' => (string) $finding['source_confidence'],
				'site_wide'         => $site_wide ? 1 : 0,
			)
		);
	}

	/**
	 * Whether a run covers the full scope, so site-wide rules can run.
	 *
	 * @param array $run Run.
	 * @return bool
	 */
	private static function full_scope( array $run ) {
		$scope = Repository::decode( $run['scope'] );
		return empty( $scope['urls'] );
	}

	/**
	 * Site rules over every page read: identity conflicts, then queue the
	 * resource checks.
	 *
	 * @param array $run Run.
	 */
	private function site_rules( array $run ) {
		$summary = Repository::decode( $run['summary'] );
		if ( self::full_scope( $run ) ) {
			$facts = $this->repo->page_facts( (int) $run['id'] );
			$urls  = $this->repo->url_index( (int) $run['id'] );
			foreach ( SiteRules::evaluate( $facts ) as $url_id => $findings ) {
				foreach ( $findings as $finding ) {
					$this->store_finding( (int) $run['id'], (int) $url_id, isset( $urls[ $url_id ] ) ? $urls[ $url_id ] : '', $finding );
				}
			}
			$summary['resources']      = SiteRules::resources( $facts );
			$summary['resource_index'] = 0;
		}
		$this->repo->update_run(
			(int) $run['id'],
			array(
				'phase'   => self::full_scope( $run ) ? 'resources' : 'reconcile',
				'summary' => (string) wp_json_encode( $summary ),
			)
		);
	}

	/**
	 * Check each distinct own-host image and logo once (URL-004).
	 *
	 * @param array $run      Run.
	 * @param float $deadline Deadline.
	 * @return bool
	 */
	private function check_resources( array $run, $deadline ) {
		list( , $fetcher ) = $this->engine();
		$summary           = Repository::decode( $run['summary'] );
		$resources         = isset( $summary['resources'] ) ? (array) $summary['resources'] : array();
		$urls              = array_keys( $resources );
		$index             = isset( $summary['resource_index'] ) ? (int) $summary['resource_index'] : 0;
		$page_urls         = $this->repo->url_index( (int) $run['id'] );
		$broken            = isset( $summary['resources_broken'] ) ? (int) $summary['resources_broken'] : 0;

		while ( $index < count( $urls ) && microtime( true ) < $deadline && ! $this->should_stop( $run ) ) {
			$url    = $urls[ $index ];
			$result = $fetcher->fetch( $url, 'HEAD' );
			++$this->requests;
			if ( in_array( (int) $result['status'], array( 405, 501 ), true ) ) {
				$result = $fetcher->fetch( $url );
				++$this->requests;
			}
			if ( in_array( $result['outcome'], array( 'not_found', 'gone' ), true ) ) {
				++$broken;
				foreach ( $resources[ $url ] as $where ) {
					$url_id = (int) $where['url_id'];
					$this->store_finding( (int) $run['id'], $url_id, isset( $page_urls[ $url_id ] ) ? $page_urls[ $url_id ] : '', SiteRules::broken_resource( $url, $where, (int) $result['status'] ) );
				}
			}
			++$index;
			$this->pause( (int) $result['duration_ms'] );
		}

		$summary['resource_index']   = $index;
		$summary['resources_broken'] = $broken;
		$done                        = $index >= count( $urls );
		if ( $done ) {
			$summary['resources_checked'] = count( $urls );
			unset( $summary['resources'] );
		}
		$this->repo->update_run(
			(int) $run['id'],
			array(
				'phase'   => $done ? 'reconcile' : 'resources',
				'summary' => (string) wp_json_encode( $summary ),
			)
		);
		return $done;
	}

	/**
	 * Update the issue register and compare with the baseline.
	 *
	 * @param array $run Run.
	 */
	private function reconcile( array $run ) {
		$run_id   = (int) $run['id'];
		$baseline = $this->repo->baseline_for( $run );
		$current  = $this->repo->occurrences_by_key( $run_id );
		$findings = array();
		foreach ( $current as $key => $occ ) {
			$findings[ $key ] = array(
				'rule_id'       => $occ['rule_id'],
				'rule_version'  => (int) $occ['rule_version'],
				'observed_hash' => $occ['observed_hash'],
			);
		}
		$coverage = $this->repo->coverage_map( $run_id );
		$pages    = array();
		foreach ( $coverage as $key => $info ) {
			$pages[ $key ] = $info['coverage'];
		}
		$fingerprint = Repository::decode( $run['fingerprint'] );
		$prior       = $baseline ? Repository::decode( $baseline['fingerprint'] ) : array();
		$issues      = $this->repo->issues_by_key();
		$result      = Comparator::reconcile( $issues, $findings, $pages, $fingerprint, $prior, self::full_scope( $run ) );
		$now         = Repository::now();
		$is_baseline = empty( $prior );

		foreach ( $result['insert'] as $key => $fields ) {
			$occ = $current[ $key ];
			$id  = $this->repo->insert_issue(
				array(
					'issue_key'            => $key,
					'page_url'             => $occ['site_wide'] ? '' : substr( $occ['page_url'], 0, 2048 ),
					'site_wide'            => (int) $occ['site_wide'],
					'rule_id'              => $occ['rule_id'],
					'rule_version'         => (int) $occ['rule_version'],
					'severity'             => $occ['severity'],
					'entity_key'           => $occ['entity_key'],
					'property'             => $occ['property'],
					'first_run_id'         => $run_id,
					'last_run_id'          => $run_id,
					'first_observed_utc'   => $now,
					'last_observed_utc'    => $now,
					'verification_state'   => $fields['verification_state'],
					'verification_run_id'  => $run_id,
					'change_reason'        => $fields['change_reason'],
					'observed_hash'        => $fields['observed_hash'],
					'latest_occurrence_id' => (int) $occ['id'],
					'work_status'          => 'open',
					'updated_utc'          => $now,
				)
			);
			$this->repo->link_occurrences( $run_id, $key, $id );
			if ( ! $is_baseline ) {
				$this->repo->log_event( 'detected', array( 'reason' => $fields['change_reason'] ), 0, 'issue', $id, $run_id );
			}
		}

		foreach ( $result['update'] as $key => $fields ) {
			$issue = $issues[ $key ];
			if ( isset( $current[ $key ] ) ) {
				$fields['last_run_id']          = $run_id;
				$fields['last_observed_utc']    = $now;
				$fields['latest_occurrence_id'] = (int) $current[ $key ]['id'];
				$fields['severity']             = $current[ $key ]['severity'];
				$this->repo->link_occurrences( $run_id, $key, (int) $issue['id'] );
			}
			if ( isset( $fields['verification_state'] ) ) {
				$fields['verification_run_id'] = $run_id;
				if ( $fields['verification_state'] !== $issue['verification_state'] ) {
					$this->repo->log_event(
						'verification',
						array(
							'from' => $issue['verification_state'],
							'to'   => $fields['verification_state'],
						),
						0,
						'issue',
						(int) $issue['id'],
						$run_id
					);
				}
			}
			$this->repo->update_issue( (int) $issue['id'], $fields );
		}
		foreach ( $result['events'] as $event ) {
			list( $key, $type, $message ) = $event;
			if ( isset( $issues[ $key ] ) ) {
				$this->repo->log_event( $type, array( 'message' => $message ), 0, 'issue', (int) $issues[ $key ]['id'], $run_id );
			}
		}

		$summary                = Repository::decode( $run['summary'] );
		$summary['register']    = $result['summary'];
		$summary['coverage']    = $this->repo->coverage_counts( $run_id );
		$summary['severity']    = $this->repo->severity_counts( $run_id );
		$summary['findings']    = count( $current );
		$summary['is_baseline'] = $is_baseline;
		if ( $baseline && self::full_scope( $run ) ) {
			$summary['comparison'] = $this->comparison_counts( $baseline, $run_id, $current, $coverage );
		}
		$this->repo->update_run(
			$run_id,
			array(
				'phase'           => 'notify',
				'baseline_run_id' => $baseline ? (int) $baseline['id'] : 0,
				'summary'         => (string) wp_json_encode( $summary ),
			)
		);
	}

	/**
	 * Comparison with the baseline, as counts (the digest carries counts only).
	 *
	 * @param array $baseline Baseline run.
	 * @param int   $run_id   Run ID.
	 * @param array $current  Current occurrences by key.
	 * @param array $coverage Current coverage map.
	 * @return array
	 */
	private function comparison_counts( array $baseline, $run_id, array $current, array $coverage ) {
		$shape = static function ( array $occurrences, array $pages, $fingerprint ) {
			$findings = array();
			foreach ( $occurrences as $key => $occ ) {
				$findings[ $key ] = array(
					'hash'    => $occ['observed_hash'],
					'rule_id' => $occ['rule_id'],
					'page'    => $occ['site_wide'] ? '' : Evaluator::url_key( $occ['page_url'] ),
				);
			}
			return array(
				'findings'    => $findings,
				'pages'       => $pages,
				'fingerprint' => $fingerprint,
			);
		};
		$before = $shape( $this->repo->occurrences_by_key( (int) $baseline['id'] ), $this->repo->coverage_map( (int) $baseline['id'] ), Repository::decode( $baseline['fingerprint'] ) );
		$run    = $this->repo->get_run( $run_id );
		$after  = $shape( $current, $coverage, Repository::decode( $run['fingerprint'] ) );
		$ever   = array();
		foreach ( $this->repo->issues_by_key() as $key => $issue ) {
			if ( (int) $issue['first_run_id'] < (int) $baseline['id'] ) {
				$ever[ $key ] = true;
			}
		}
		$comparison = Comparator::compare( $before, $after, $ever );
		$counts     = array( 'meaningful' => Comparator::is_meaningful( $comparison ) );
		foreach ( $comparison as $list => $items ) {
			$counts[ $list ] = count( $items );
		}
		$counts['rules_changed_ids'] = $comparison['rules_changed'];
		return $counts;
	}

	/**
	 * Final state, outbox and retention.
	 *
	 * @param array $run Run.
	 */
	private function notify( array $run ) {
		$counts  = $this->repo->coverage_counts( (int) $run['id'] );
		$ok      = isset( $counts['ok'] ) ? $counts['ok'] : 0;
		$unknown = 0;
		foreach ( Comparator::UNKNOWN as $state ) {
			$unknown += isset( $counts[ $state ] ) ? $counts[ $state ] : 0;
		}
		$state = 'complete';
		if ( 0 === $ok && (int) $run['url_count'] > 0 ) {
			$state = 'failed';
		} elseif ( $unknown > 0 ) {
			$state = 'partial';
		}
		$this->finish( $run, $state );
		$run = $this->repo->get_run( (int) $run['id'] );
		if ( 'monthly' === $run['run_type'] ) {
			Outbox::queue_for_run( $run );
		}
		Retention::apply();
	}

	/**
	 * Close a run.
	 *
	 * @param array  $run   Run.
	 * @param string $state Final state.
	 * @param array  $extra Extra summary fields.
	 */
	private function finish( array $run, $state, array $extra = array() ) {
		$summary = array_merge( Repository::decode( $run['summary'] ), $extra );
		$this->repo->update_run(
			(int) $run['id'],
			array(
				'state'        => $state,
				'phase'        => 'done',
				'finished_utc' => Repository::now(),
				'summary'      => (string) wp_json_encode( $summary ),
			)
		);
		$this->repo->log_event( 'run_finished', array( 'state' => $state ), 0, 'run', (int) $run['id'], (int) $run['id'] );
	}

	/**
	 * Progress for screens and the CLI.
	 *
	 * @param int    $run_id Run ID.
	 * @param string $note   Note.
	 * @return array
	 */
	private function status( $run_id, $note ) {
		$run = $this->repo->get_run( $run_id );
		return array(
			'run_id' => (int) $run_id,
			'note'   => $note,
			'state'  => $run ? $run['state'] : 'missing',
			'phase'  => $run ? $run['phase'] : '',
			'done'   => $run ? (int) $run['done_count'] : 0,
			'total'  => $run ? (int) $run['url_count'] : 0,
		);
	}
}
