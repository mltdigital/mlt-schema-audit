# Server cron hand-over note (Guru Hosting cPanel servers)

For whoever sets up MLT Schema Audit on the two Guru Hosting servers. 30 October 2026.

> Do not set this up on any client or pilot site until Gav C has signed off the contract and threat model and a developer has reviewed the security-sensitive code. Several facts below are **Input needed**: confirm them first.

## Why a server cron job

WordPress cron only runs when someone visits the site, and each visit gets a short time budget (about 20 seconds). A large site audited that way can take hours. A server cron job running WP-CLI gives the worker a long budget, so a 500-page audit finishes in a few cron intervals.

## Recommended job (per cPanel account)

Every five minutes, with a budget just under five minutes so jobs never overlap:

```
*/5 * * * * cd /home/ACCOUNT/public_html && /usr/local/bin/php /usr/local/bin/wp mltsa tick --budget=240 --quiet >/dev/null 2>&1
```

- Replace `ACCOUNT` and the paths. **Input needed:** the PHP binary path, whether WP-CLI is installed on each server, and its path (brief question 3).
- A run holds a lock, so an overlapping job does nothing harmful: it finds the run locked and exits.
- `wp mltsa status` prints the latest runs and the same checks as the Health screen.

If WP-CLI is not available, use WordPress's own cron endpoint instead (shorter budget per call):

```
*/5 * * * * curl -s -o /dev/null "https://SITE/wp-cron.php?doing_wp_cron"
```

With either option, consider `define( 'DISABLE_WP_CRON', true );` in `wp-config.php` so visitors never trigger audit work. The Health screen then warns if nothing has run the scheduler for 15 minutes while an audit is waiting.

## Staggering (threat S1)

Each site audits one page at a time with a one-second gap, and backs off when the site is slow. Even so, do not start every site on one server at once.

- Give each site on a server a different schedule within the first week: for example first Monday, first Tuesday and so on, and different times (09:00, 11:00, 14:00).
- **Input needed:** the number of sites per server, to check the stagger plan fits the week.

## Security tools and Cloudflare (threat F8)

The plugin requests the site's own pages from the server it runs on. Server security tools may treat that as an attack.

- User agent: `MLT-Schema-Audit/<version> (+<site home URL>)`. Ask Guru Hosting to allowlist it in ModSecurity and Imunify360 if they block it.
- If the site is behind Cloudflare, requests may leave the server and come back through Cloudflare. Check that Cloudflare does not challenge the user agent.
- **Input needed:** CloudLinux limits, ModSecurity, Imunify360 and Cloudflare per server (brief question 4).

## Spike checklist for the first site on each server

1. Install on a staging copy on that server, not a client site. Leave monitoring off.
2. Health screen: **Connection pinning** must be OK (cURL present). Without it every fetch is refused.
3. Run a manual audit of the staging copy. Check coverage: pages read should equal pages in scope. Blocked or timed-out pages point at F8.
4. Watch server load during the audit (CloudLinux LVE usage). Record time per page.
5. Check the server's security logs for blocks against the user agent.
6. Confirm the cron job runs: **Scheduler, last tick** on the Health screen updates every five minutes.
7. Mail: on staging the clone guard pauses mail. On the live site, after sign-off, send one test by running a monthly audit with an MLT recipient, and check the WP Mail SMTP log and SparkPost.

## What could not be verified locally

- Behaviour on the Guru Hosting servers: PHP and WordPress versions, cURL resolve pinning, ModSecurity, Imunify360, Cloudflare and CloudLinux limits.
- Delivery through WP Mail SMTP and SparkPost. Locally, every `wp_mail()` call was logged by a development mu-plugin and nothing was sent.
- PHP 7.4 at runtime. The code passes the PHP 7.4 compatibility sniffs, but the tests ran on PHP 8.5 only.
