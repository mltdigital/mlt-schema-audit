# Changelog

All notable changes to MLT Schema Audit. Dates are UK dates. Versions follow semantic versioning; nothing has been released yet.

## Unreleased (0.1.0)

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
