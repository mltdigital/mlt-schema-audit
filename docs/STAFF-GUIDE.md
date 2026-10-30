# MLT Schema Audit: staff guide

For MLT delivery and client services staff. Version 0.1.0, 30 October 2026.

> **Not yet approved for client or pilot sites.** Nothing is installed on a client or pilot site until Gav C has signed off the product contract and threat model and a developer has reviewed the security-sensitive code.

## What it does, in short

- Reads the structured data (JSON-LD) in the HTML this site sends, page by page, and reports problems.
- Never creates, edits, repairs or removes schema, page content or another plugin's data. It only reads.
- Keeps a register of findings, so each month shows what is new, what changed and what is no longer detected.
- Can run once a month and email named people when something meaningful changed.

What it does not see: markup added by JavaScript after the page loads, and anything not in the server's response. Microdata and RDFa are counted but not checked. "No JSON-LD detected" never means "no structured data". Every screen and export says this.

## Who can use it

| Capability | Who has it by default | What it allows |
|---|---|---|
| `mltsa_audit` | Administrators | Run audits, read findings and evidence, change statuses, add notes, export |
| `mltsa_manage` | Administrators | Recipients, schedule, scope, limits, retention, the kill switch |

Client staff who are administrators have both. **Anything you write in a note can be read by client staff.** Write notes fit for the client to read, with no internal opinions about the client or their staff.

## Running a manual audit

1. Go to **Schema Audit, Audits** and select **Start audit**.
2. Keep the screen open to move it along quickly. It also continues in the background through the scheduler.
3. When it finishes, open the audit to see pages read, pages left out and why, and how it compares with the previous audit.

Only one audit runs at a time. A second start is refused while one is in progress.

## Reading findings

Open **Findings** (or **View findings** on an audit). Each finding has:

- **Group**: Confirmed errors, Potential conflicts, Eligibility restrictions, Optional improvements.
- **Outcome**: Fail (a confirmed defect) or Review (needs a person to judge). Review is not proof of an error.
- **Severity** (how much it matters) and **confidence** (how sure the audit is). They are separate.
- **Evidence**: the value observed, what it was compared with, the block and JSON path, and a short snippet (at most 500 characters).

Open a finding to read what the rule checks, why it matters and what to check next.

Common cases from the pilot:

| You see | What it usually means |
|---|---|
| FEAT-001 Ratings on the firm's own business | Self-serving review stars. Not invalid, but not eligible for review snippets |
| FACT-001 Telephone not found on the page | The schema number is not shown or linked on the page. It may be a typo, or a real unpublished line: ask the client before calling it an error |
| FACT-007 Postcode contradicted by the page | The page prints the same street with a different postcode. Very likely wrong |
| ID-005, SITE-002 Same business declared more than once | Several unlinked descriptions of one firm, often from two plugins |
| URL-004 Linked file or page returns not found | A logo, image or profile page on this site returns 404 |

## Work status and verification

You set the **work status**: Open, In progress, Awaiting client evidence, Ready for verification, Resolved, Accepted exception, False positive.

- **Accepted exception** and **False positive** need a reason, a reviewer and a review date.
- If the evidence behind an exception or false positive changes, the scanner reopens it.

Only the scanner sets the **verification state**: Present, Changed, Returned, No longer detected, Page removed or redirected, Unavailable.

- Marking a finding **Resolved** does not verify it. To confirm a fix, tick the finding and select **Recheck**, or wait for the next monthly audit.
- A timeout, an excluded page, a removed rule or a smaller scope never sets "No longer detected".
- "New because a rule changed" means the audit changed, not the website.

## Exports

On an audit, select **Download ZIP** for Summary, Pages, Findings and Change log as CSV files plus `manifest.json`, or download any CSV on its own. A filtered view exports only what is shown, and the manifest and Summary say it is filtered.

Cells that start with `=`, `+`, `-` or `@` are prefixed with an apostrophe so Excel never runs them as formulas. Exports are streamed to your browser; nothing is saved on the server. Treat a downloaded export as client data: keep it in approved MLT storage and delete local copies when done.

## Setting up monthly monitoring

In **Settings** (needs `mltsa_manage`):

1. **Scope**: choose the content types. The homepage is always included. Tick **The scope is confirmed**.
2. **Schedule**: for example first Monday at 09:00, Europe/London. The screen shows the next three dates. **Stagger sites on the same server** across the first week (see the server cron note). Tick **The schedule is confirmed**.
3. **Recipients**: named MLT or client addresses, one per line, at most 10. The site's admin address is never used.
4. Tick **Run the monthly audit and send the email** and save. It cannot be switched on until steps 1 to 3 are done.

The email carries the site address, the date, counts and a login link. It never contains page titles, page addresses, evidence or notes. It is sent when something meaningful changed, on the first audit, or when an audit could not read every page (labelled as an operational alert, never an all-clear). "Submitted" on the Health screen means the site handed the email to its mail system; it does not prove delivery.

## Clones, staging copies and migrations

Recipients are confirmed against the site's address. If the address changes, all mail pauses and the Health screen says why. On the real site after a migration, open Settings, tick **Reconfirm these recipients** and save. On a staging copy, do not reconfirm.

## Stopping it quickly

- **Kill switch setting** (Settings): stops scheduling and mail now, and cancels a monthly audit in progress. Manual audits still work.
- **`define( 'MLTSA_DISABLE', true );`** in `wp-config.php`: stops scheduling, mail and manual audits. Use this across many sites at once.

## Health screen

Shows, in plain English: kill switch, monitoring and the next start, recipients and any mail pause, the outbox, the scheduler's last run, the audit in progress, connection pinning, and versions. Check it after setup and whenever an email does not arrive.

## Removing the plugin

Deactivating clears every scheduled event and keeps the data. Deleting the plugin removes its settings and capabilities; it removes the audit tables and history only if **Remove all audit data when the plugin is deleted** was ticked beforehand. It never touches the MLT Schema Automation plugin or its data.
