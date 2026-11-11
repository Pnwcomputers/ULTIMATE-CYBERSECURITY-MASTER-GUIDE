# Protected Main Ruleset: Admin Setup & Verification

_Configuration review: November 11, 2026 · Repository: `Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE` · [Existing ruleset](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/rules/10087669)._

## Verified Gap

GitHub's live ruleset API reports an active `Protect main branch` ruleset targeting `refs/heads/main` with **deletion**, **non-fast-forward**, **required linear history**, **creation** and **update** restrictions. It **does not** have a required pull-request rule or named required-status-check rules. Its bypass list includes repository roles, integrations and deploy keys; those exemptions must be reviewed before treating the branch as fully gated. The app connection available for this audit can read rulesets but **cannot administer them**; a Markdown PR cannot activate these protections.

## Apply In GitHub With Repository Admin Permissions

1. Open [Settings → Rules → Rulesets → Protect main branch](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/rules/10087669). Confirm it is the repository ruleset, active, and targets only `main`; check other matching rulesets/legacy branch protection too.
2. **Preserve** deletion prevention, non-fast-forward, and linear-history restrictions unless there is a separately reviewed reason to change them. Inspect **Restrict updates**, **Restrict creations**, and each bypass actor: a broad "Always" bypass means PR/CI requirements do not necessarily stop that actor. Replace broad bypasses with the smallest recovery-authorized set as operationally possible.
3. Add **Require a pull request before merging**. For a solo maintainer, set **required approvals to 0** initially; do not enable "Require review from Code Owners" or "Approve most recent reviewable push" if there is no independent eligible reviewer. This still enforces a PR route for non-bypass actors; it does *not* provide independent human review. Add genuine review requirements once a second maintainer can approve.
4. Add **Require status checks to pass**. Select actual check contexts from recent successful PR runs, after the workflows in this repository have been updated to emit them **for every pull request**. Suggested stable job contexts:

   | Required CI context | Workflow | Gate |
   |---|---|---|
   | `Internal links (offline)` | Link Check | Relative Markdown links & fragments |
   | `Lint changed Markdown` | Markdown Lint | Changed Markdown syntax/style (job passes without changed Markdown) |
   | `Guide fixtures (isolated)` | Guide tool and lab checks | Sanitized regression fixtures, no live lab |
   | `Repository syntax (static only)` | Repository Static Syntax | Maintained Python, Bash and PowerShell parser checks |
   | `Duplicate sections` | Duplicate Markdown sections | Same-page repeated headings |
   | `Numbered lists` | Markdown numbered list integrity | Navigation/numbering |

   **Important:** GitHub required contexts must match *observed* job names exactly, not guesses. Confirm the displayed names after a fresh successful PR. Do not add informational or scheduled-only jobs (`External links (online, informational)`, Maintenance Triage, Changelog) as required contexts. A workflow restricted by path filters cannot reliably supply a required check on unrelated PRs; this audit removes the PR path filters from the six proposed gates.
5. If the platform exposes **Block force pushes**, **Require conversation resolution**, or **Restrict bypass to pull requests**, evaluate those along with the existing protection, documenting the actual selection. For solo maintenance, maintain a narrowly authorized, documented emergency recovery actor rather than granting all roles unconditional bypass.
6. Save, then verify by deliberately introducing a harmless failing Markdown/fixture change **in a disposable test PR**: the merge must be blocked for non-bypass roles. Do **not** merge the failing test. Correct it and confirm a green run becomes mergeable. Record ruleset snapshot date, the test PR URL, failed/pass contexts and whether the acting identity was eligible to bypass.

## Why This Cannot Be Closed By A Documentation PR

Rule settings live in GitHub's repository security administration, not in versioned README, CODEOWNERS or a workflow. The connected GitHub tool can update source files and inspect the ruleset but does not offer an authorized ruleset PUT/PATCH. Until an administrator changes the settings and the safe negative test proves enforcement, [issue #186](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/issues/186) must remain open.

References: [GitHub: Available rules for rulesets](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets), [Creating rulesets](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/creating-rulesets-for-a-repository), [Troubleshooting required status checks](https://docs.github.com/en/pull-requests/how-tos/merge-and-close-pull-requests/troubleshooting-required-status-checks).

---

[Maintenance Operations](REPOSITORY-MAINTENANCE-OPERATIONS.md) · [Verification Protocol](REPOSITORY-VERIFICATION-PROTOCOL.md) · [Main Index](../README.md)
