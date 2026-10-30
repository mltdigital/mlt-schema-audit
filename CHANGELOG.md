# Changelog

All notable changes to MLT Schema Audit. Dates are UK dates. Versions follow semantic versioning; nothing has been released yet.

## Unreleased (0.1.0)

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
