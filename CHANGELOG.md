# Changelog

All notable changes to MLT Schema Audit. Dates are UK dates. Versions follow semantic versioning; nothing has been released yet.

## Unreleased (0.1.0)

### Review fixes (30 October 2026)

Two code reviews on 30 October found defects to fix before any pilot. Fixed so far:

- Private-address check (review finding 1): IP addresses are now classified by their bytes, not their spelling. `::ffff:7f00:1`, `0:0:0:0:0:0:0:1`, NAT64 and 6to4 forms of loopback, private and metadata addresses were treated as public and are now refused.
- Denied paths (review finding 11): the admin, login, XML-RPC and REST deny list is now checked against the path as a server would read it (decoded, dot segments and repeated slashes removed), so `/public/../wp-admin/`, `/%2e%2e/wp-admin/` and `//wp-admin/` are refused, including in absolute redirect locations. Frozen URLs have dot segments removed.
- Site-wide issues (review finding 2): a site-wide issue (SITE-001, SITE-002, SITE-003, ID-003, URL-004) is now cleared only when every page it rests on was read again, or has gone, and, for a broken image or logo, the image was checked again or no page read still uses it. Before, any full-scope run with no matching finding cleared it, even when its pages timed out or had dropped out of scope. The evidence is stored on the issue in a new `evidence` column (database version 2). A page that could not be read, or an image over the 200-image cap, sets the issue to "Unavailable"; a page outside the run leaves it untouched. SITE-001 evidence includes every page carrying the business, not only the page that differs. Issues stored before this change clear only when every page in the run was read. The digest's "resolved" count follows the same rule.
- Image and logo checks (review finding 3): the `/wp-content/` and `/wp-includes/` deny rule stopped URL-004 checking any image in the media library, so broken uploads were never reported. Image and logo checks now use a wider path policy: static image, PDF and video files in those folders may be requested, on every redirect hop; scripts never (no `.php` or other script extension anywhere in the path, so `run.php/a.png` and `a.php.png` are refused), and page fetches still refuse both folders. Each run records images referenced, requested, checked (an answer received) and broken, shown on the audit screen and in the export summary; an image that was not checked keeps its issue open.
- Worker budget and recovery (review finding 4): no request can now outlive the worker's time budget. Each request's timeout is the lower of the timeout setting and the time left; a request the budget cut short, or a retry there was no time left to wait for, is "deferred", not recorded as a timeout. The page or image stays pending and the slice ends, so the next slice starts with it and a full budget; on its third deferral it is recorded as a timeout (reason `budget_timeout`) or an error (reason `budget_spent`). Image checks now record each attempt before the request, as page fetches already did, so an image that kills the process is given up after three attempts (reason `worker_stopped`). Sitemap discovery reads one sitemap per step, with progress in the `mltsa_discovery_state` option (removed when the run finishes and on uninstall). Each tick queues its own continuation before it starts work (budget plus 150 seconds, after the run lock has expired), so a process killed part way through no longer leaves the audit stranded; a normal finish brings it forward to 30 seconds. A new hourly `mltsa_watchdog` event requeues the worker for an active run that has no worker event, and logs `worker_restarted` against the run.
- Outbox scheduling (review finding 5): a failed send is retried 5, then 10 minutes later, but nothing queued an event for that time, so the retry waited for whatever cron event came next (on a quiet month, the next monthly run). The outbox now keeps one `mltsa_outbox` event at the moment it next has work: the earliest pending retry, or the moment a claim on an interrupted send expires. Due rows are read earliest first, so rows waiting for a retry no longer fill the per-call limit and hold back rows that are due. While mail is blocked (kill switch, no recipients, home URL changed) no event is queued; saving settings or reconfirming recipients queues one, and the hourly watchdog puts back a lost one.

Still open: findings 6 to 10 of the first review and the confirmed items of the second (see `STATE.md` in the project folder).

### Stage 7: documents and release build

- Staff guide, server cron hand-over note for the Guru Hosting servers, contract revision notes, README.
- `bin/build-release.php`: release ZIP from git-tracked files matching an explicit allowlist (plugin code, assets and this changelog only), with checks for uncommitted changes, version agreement, client names and development switches; reproducible bytes and a SHA-256 checksum; fails if the ZIP holds anything outside the allowlist.

### Stage 6: tests and static analysis

- 105 unit tests (`php tests/run-tests.php`, no WordPress needed): every acceptance case that is pure logic, threats F1 to F7, M1, M2, E1, E2, D1 and F6 at the discovery level, plus the 72 fixture cases.
- 17 integration tests (`wp eval-file tests/integration/run.php` on the disposable site; set `MLTSA_IT_FULL=1` for the 500-URL gate): S2, S3, S4 (setting and constant), M2 to M6, A1 to A6, E1, E2, D2, the schedule, catch-up, recipient rebuild and both uninstall paths. A6 compares every non-plugin table and option before and after activation, an audit, an export, a scheduled start, deactivation and uninstall.
- PHPCS with WordPress-Extra, the WordPress security and database sniffs, and PHP 7.4 compatibility (`composer install`, then `vendor/bin/phpcs`): no errors or warnings. Development dependencies only, pinned in `composer.lock`; the plugin has no runtime dependencies.
- Each request handler now calls `check_admin_referer()` itself, so the nonce check is visible where input is read.

### Stage 5: monthly operations, verified

- Proven on the disposable site by `tests/integration/run.php` (16 tests): monitoring cannot be switched on until scope, recipients and schedule are confirmed, then exactly one start is scheduled; deactivation leaves no `mltsa_` event; reactivation rebuilds the next start only; a missed month runs once as a catch-up with its lateness recorded; a second start for the same month, or any start while a run is in progress, is refused; the kill switch setting cancels a monthly run without another request while manual audits still start; `MLTSA_DISABLE` stops manual starts, the worker and mail; no recipients means no mail and never `admin_email`; a clone or staging copy pauses all mail until recipients are reconfirmed; an interrupted send becomes `delivery_unknown` and is never resent; failures retry at most three times; a recipient change rebuilds unsent notifications.
- Added `Settings::reconfirm_recipients()`, logged with both addresses, for lifting the clone pause.
- Deactivation now forgets when monitoring started, so a reactivation never catches up a month missed while the plugin was off.

### Stage 4: manual workflow

- Admin screens under Schema Audit: Audits (start, live progress, run list), one audit (coverage, exclusions with reasons, comparison with the previous audit, pages), Findings (filters by audit, group, severity, outcome, status, rule and text; recheck of ticked findings), one finding (rule explanation, evidence as plain text, work status, owner, due date, external link, exception reason, reviewer and date, notes, history), Settings and Health.
- Work statuses as the contract lists them; an accepted exception or false positive needs a reason, a reviewer and a review date. Verification state is set only by the scanner, and marking a finding Resolved does not verify it.
- Export: a ZIP of Summary, Pages, Findings and Change log CSV files plus `manifest.json`, or any CSV on its own, streamed from memory (a small ZIP writer, because ZipArchive needs a file on disk). Filtered exports say so in the manifest and the Summary sheet. Cells that start with `=`, `+`, `-`, `@`, tab or carriage return are neutralised; every cell is quoted, so leading zeros and line breaks survive; UTF-8 with a byte-order mark.
- Recheck: starts a run for the pages behind selected findings, using page URLs from the register, never from the request. Site-wide findings are rechecked by a full audit.
- Every handler checks a capability and a nonce first; there are no REST routes and nothing for logged-out users. While an audit screen is open, a script keeps the audit moving in short steps (text only, never markup).

### Historical fixtures and rule set 2026.10.2

- 71 anonymised fixtures in `tests/fixtures/historical/` (D01 to D50, FP01 to FP21), one per entry in the July to August pilot defect catalogue, plus the publishing plugin's golden pass reference in `tests/fixtures/regression/`. Fictional firms on reserved `.example` hosts, Ofcom drama-range numbers; a test fails if a client name or a non-fictional number appears. Every defect is detected as the catalogue expects; every must-not-flag case is clean. Four defects (D09, D26, D43, D47) need external references or text heuristics the catalogue itself marks optional; their fixtures assert only that nothing fails.
- 21 new rules: SYN-008 (branch modelled as a place), SYN-009 (misspelt property), SYN-010 (empty typed entity), SYN-011 (property on the wrong type), ID-004 (same address, different phones), ID-005 (same business declared twice without a link), FACT-007 (postcode contradicted by the page, a fail), FACT-008 (one street, two postcodes), FACT-009 (site name not in the page body), FACT-010 (phone printed beside another office), FACT-011 (legalName is a trading name), FACT-012 (company number not on the page), URL-006 (url and mainEntityOfPage disagree), URL-007 (cache or CDN revision path), REL-003 (description names a place the page never mentions), REL-004 (registrar as a membership), REL-005 (one URL, several WebPage or WebSite entities), REL-006 (office on the page declared by no business), FEAT-008 (reviews collected by another site), SITE-002 (one business under several unlinked @ids), SITE-003 (WebSite or WebPage @id inconsistent across pages).
- Changed rules, each bumped to version 2: ID-001 also compares logo, aggregateRating and breadcrumb items; ID-003 is judged across the whole site, so an @id defined on another page is not dangling, and an @id without a fragment is never reported; FACT-001 sees `tel:` links that contain spaces; FACT-003 matches a brand written as one word and branch names shown as brand plus town; URL-001 also catches a copy of the site on another server; URL-004 also checks own-host `sameAs` pages; URL-005 catches leading and trailing spaces and checks `mainEntityOfPage`; SITE-001 also compares logos and ratings and is now a review, not a fail, as the catalogue requires.

### Stage 3: the plugin activates and audits

- Settings in one option (`mltsa_settings`, not autoloaded), sanitised on save, with every change logged to the event table. Recipient changes are logged as counts only and confirm the recipients on the current home URL.
- Monthly calendar maths (first to fourth or last weekday, local time, explicit timezone) in a pure class with a schedule key per month.
- Scheduler: one single event for the next occurrence, catch-up for a missed occurrence (never a backlog), start mutex, and refusal of a second run while one is in progress.
- Repository: every query in one class, all variables prepared.
- Discovery: homepage, published posts of chosen public types, optional capped same-host sitemaps; exclusions recorded with reasons; drafts and private content never queried.
- Resumable worker: discover, fetch, site rules, resource checks, reconcile, notify. One request at a time, gap between requests, longer waits when the site is slow, a lock per run, and every URL written once.
- Outbox, digest and retention classes (completed in stage 5).
- WP-CLI: `wp mltsa tick`, `wp mltsa audit [--wait]`, `wp mltsa status`.
- Fixed: the HTTP client read response headers by casting the Requests header dictionary to an array, which returned its private storage, so `Location` and `Content-Type` were never seen and every redirect was recorded as an HTTP error.
- Fixed: plain permalinks (`?p=12`) were stripped to the homepage by the query-string rule. Permalinks WordPress generates keep their query string; the request policy still refuses action, nonce and REST queries.

### Stages 1 and 2

- Audit engine: safe fetch (own host only, address checks at every hop, connection pinning), JSON-LD extraction, graph, 31 versioned rules, run comparison.
- Bootstrap and installer: seven `mltsa_` tables, two capabilities, lifecycle hooks.
