# MLT Schema Audit

A read-only WordPress plugin that audits the JSON-LD structured data in a site's own server responses, keeps a register of findings across runs, and can email a monthly change summary. It never creates, edits, repairs or removes schema, page content or another plugin's data.

Version 0.1.0, unreleased. **Not approved for any client or pilot site** until Gav C (CTO) has signed off the product contract and threat model and a developer has reviewed the security-sensitive code (fetch, access control, storage, export, mail).

## Documents

- [Staff guide](docs/STAFF-GUIDE.md): using the plugin.
- [Server cron hand-over](docs/SERVER-CRON.md): cron, staggering, security tools, the first-site spike checklist.
- [Contract revision notes](docs/CONTRACT-REVISION-NOTES.md): defaults changed during the build, to append to the contract at sign-off.
- [Changelog](CHANGELOG.md).
- The product contract and threat model live with the project records, outside this repository.

## Requirements

PHP 7.4 or later with cURL (requests are pinned to the checked address), WordPress 5.8 or later. No runtime dependencies. Both minimums are provisional until the server inventory is known.

## Layout

| Path | What |
|---|---|
| `mlt-schema-audit.php`, `uninstall.php` | Bootstrap and uninstall |
| `includes/Engine/` | Pure PHP audit engine: URL policy, fetcher, extractor, graph, rules, evaluator, site rules, comparator |
| `includes/Ops/` | Calendar, scheduler, worker, outbox, digest, retention |
| `includes/Store/Repository.php` | Every database query |
| `includes/Admin/`, `includes/Export/` | Screens, handlers, health checks, CSV and ZIP export |
| `tests/unit/`, `tests/fixtures/` | Unit tests and the 71 anonymised historical fixtures |
| `tests/integration/run.php` | Integration tests for a disposable local site |
| `bin/build-release.php` | Allowlisted release build |

## Development

Tests and builds run only against a disposable local WordPress (`.dev/wp`, gitignored, mail blocked, no client data). Never against a client or pilot site.

```bash
php tests/run-tests.php
```

```bash
composer install && vendor/bin/phpcs
```

Integration tests need the local site served on IPv4 (an IPv6-only bind makes every pinned fetch fail) and the plugin active there:

```bash
PHP_CLI_SERVER_WORKERS=4 php -S 127.0.0.1:8899 -t .dev/wp
```

```bash
wp --path=.dev/wp eval-file "$PWD/tests/integration/run.php"
```

Set `MLTSA_IT_FULL=1` to include the 500-URL audit. On the local site the plugin folder is a symlink to this repository: never run `wp plugin uninstall` or `wp plugin delete` there, because WordPress would delete the source.

## Release

```bash
php bin/build-release.php
```

Builds `dist/mlt-schema-audit-<version>.zip` and a `.sha256` file from git-tracked files that match the allowlist in the script, and fails if anything else would ship. The same commit always produces the same checksum. `php bin/build-release.php --check` re-verifies an existing build.

## Fixtures and client data

Fixtures use fictional firms on reserved `.example` hosts and Ofcom drama-range numbers. A unit test fails if a client name or a non-fictional UK number appears in them. The mapping back to the pilot evidence stays outside git.
