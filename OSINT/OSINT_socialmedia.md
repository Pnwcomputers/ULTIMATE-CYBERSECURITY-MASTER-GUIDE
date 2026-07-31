# 🕵️ Social Media OSINT

## 🎯 Purpose
Methodology and tooling for collecting **publicly available** intelligence from social platforms during authorized engagements - covering cross-platform pivots, per-platform collection notes, and defensible evidence handling for the OSINT Investigator Playbook.

## ⚙️ Function
Documents the durable social media OSINT workflow: investigator OPSEC (research accounts, compartmentalization, behavioral hygiene), platform-agnostic pivots (username enumeration, numeric ID anchoring, search-engine dorking, reverse image search, archive recovery, contact enumeration), and platform-specific collection for Meta, X, TikTok, LinkedIn, Reddit, the Fediverse/Bluesky, and Snapchat/Telegram/Discord - plus evidence capture and chain-of-custody practices.

## 🏆 Goal
Serve as the authoritative social media reference for the OSINT Investigator Playbook, giving practitioners a methodology that survives platform churn and the tradecraft to collect, attribute, and preserve social artifacts to a reportable/evidentiary standard.

## 📋 When to Use
- Building a subject's social media footprint during an investigation
- Pivoting a known username, real name, or profile image across platforms
- Recovering deleted, renamed, or archived accounts and posts
- Capturing social media artifacts for a client report or legal process
- Deciding which platform and collection method fits the available selectors

---

## ⚠️ Read This First

Social media OSINT is the most volatile discipline in this guide. Platforms actively fight enumeration and scraping, kill undocumented endpoints without notice, and rotate URL structures. **Assume any platform-specific trick below has a shelf life measured in months.** The *methodology* is durable; the *implementation details* are not.

Nothing here requires exploiting a vulnerability or bypassing authentication - every technique operates on data the target (or a third party) chose to make public. Even so:

- **Stay in scope.** Only collect against targets covered by your rules of engagement, warrant, or client authorization. "Publicly available" is not the same as "in scope."
- **Minimize.** Collect what the objective requires. Incidental third-party data (friends, commenters, bystanders) should be handled and retained accordingly.
- **Know your jurisdiction.** Pretexting, ToS violations, and automated collection carry different legal weight depending on where you and the target sit. Consult the Legal & Ethical Notice in the [OSINT section README](README.md) before an engagement.

---

## 🧰 Toolkit

The workflow leans on the following tools for enumeration, capture, and recovery:

| Tool | Category | Primary Function |
| --- | --- | --- |
| [Sherlock](https://github.com/sherlock-project/sherlock) | Enumeration | Username search across 400+ platforms. |
| [Maigret](https://github.com/soxoj/maigret) | Enumeration | Username search with profile parsing and metadata extraction. |
| [WhatsMyName](https://whatsmyname.app/) | Enumeration | Community-maintained username presence checking (web + [data](https://github.com/WebBreacher/WhatsMyName)). |
| [yt-dlp](https://github.com/yt-dlp/yt-dlp) | Capture | Video + platform metadata download (TikTok, YouTube, and many others). |
| [gallery-dl](https://github.com/mikf/gallery-dl) | Capture | Bulk image/media download across many social platforms. |
| [Instaloader](https://instaloader.github.io/) | Capture | Instagram profile and media capture (login required for most targets). |
| [ExifTool](https://exiftool.org/) | Metadata | Metadata extraction from downloaded media. |
| [waybackpy](https://github.com/akamhy/waybackpy) / [gau](https://github.com/lc/gau) | Recovery | Historical and deleted content recovery via web archives. |
| [memory.lol](https://github.com/travisbrown/memory.lol) | Recovery | X/Twitter handle-history and numeric-ID correlation. |
| [Firefox Multi-Account Containers](https://addons.mozilla.org/en-US/firefox/addon/multi-account-containers/) | OPSEC | Per-investigation session and cookie compartmentalization. |
| [Browser Developer Tools](https://developer.mozilla.org/en-US/docs/Learn_web_development/Howto/Tools_and_setup/What_are_browser_developer_tools) | Capture | Source-of-truth media and exact-timestamp extraction (no third party in the chain). |

> Third-party "downloader" and "analytics" sites (story downloaders, follower auditors, engagement analyzers) are convenient but insert an untrusted party between you and your target, and they break constantly. Fine for triage; go to the source for anything that ends up in a report or a courtroom.

---

## 🛡️ Operational Security for the Investigator

You are the easiest thing for a target to detect. Collection posture leaks intent.

**Research ("sock puppet") accounts.** Most platforms restrict search, profile viewing, and media access to authenticated users. Maintain aged, low-signal accounts dedicated to investigation - never a personal account. Aged accounts survive scrutiny better than fresh ones; stand a few up long before you need them. Expect periodic suspensions and CAPTCHA challenges; treat them as routine.

**Compartmentalization.**
- One browser profile / container per investigation account. Firefox Multi-Account Containers or dedicated browser profiles keep cookies, sessions, and fingerprints from bleeding across cases.
- Route collection through infrastructure that isn't attributable to you or your client - a VPN or dedicated VPS, not your office egress. Repeated hits from one IP against one target are a reliable way to get flagged and to notify the target.
- Disable link previews and "who viewed your profile"-style features where the platform offers them.

**Behavioral hygiene.** Don't like, follow, connect, add-friend, or request anything unless you fully understand the notification it triggers. A stray follow or a contact-sync prompt can burn an entire operation. Read every button before you click it.

**Automation is a tripwire.** Aggressive auto-scrolling, headless scraping, and rapid sequential requests are exactly what anti-abuse systems look for. Pace collection like a human. Where you must automate, test against your own accounts first to learn the detection threshold.

---

## 🔗 Cross-Platform Methodology

Platform-specific tricks come and go. These pivots work everywhere and should form the backbone of any social media workup.

### Username pivoting
People reuse handles. A username unique enough to matter (i.e., not `mike` or `jsmith`) is one of the highest-yield selectors you have. Take every known handle, vanity string, or distinctive bio phrase and check it across every platform of interest. Targets who lock down one platform frequently leave an identically named account wide open on another - TikTok and gaming platforms are common blind spots. Automate the first pass with `sherlock`, `maigret`, or WhatsMyName, then verify manually - a matching handle is a lead, not a confirmation.

### Numeric ID vs. handle
Nearly every major platform assigns each account a **stable numeric ID** internally while exposing a **mutable handle** publicly. The handle is what changes when a target rebrands or tries to disappear; the numeric ID does not. Capture the numeric ID early - it lets you re-locate an account after a handle change and correlate the same account across a platform's various endpoints. IDs are typically recoverable from page source, an info/API endpoint, or the URL of a piece of content. Because many platforms assign IDs sequentially or in dateable ranges, the ID can also bound an account's **creation date**.

### Search-engine dorking
A platform's internal search is usually worse than Google or Bing pointed at the same platform. Use `site:` scoping plus quoted selectors:

```
site:instagram.com "targethandle"
site:instagram.com "@targethandle"           # posts mentioning the target, not the target's own
site:tiktok.com "targethandle"
site:x.com "targethandle" "instagram.com/p"   # cross-links to their other accounts
site:threads.net OR site:bsky.app OR site:mastodon.social "targethandle"
```

Repeat across Google, Bing, and Yandex - index coverage differs, and each surfaces content the others miss. Quoting a comment string or bio phrase, rather than a handle, catches mentions the target doesn't control.

### Reverse image search on profile media
Profile photos and avatars are frequently reused across platforms and dating/forum accounts. Pull the **highest-resolution** version available (thumbnails defeat the match) and run it through Google Lens, Yandex, PimEyes, and TinEye. This is often the fastest way to jump from one account to a target's broader footprint. See [OSINT_TOOLS_CATALOG.md](OSINT_TOOLS_CATALOG.md) for the reverse-image and facial-recognition tooling.

### Deleted & historical content
Deletion on the client is not deletion everywhere.
- **Wayback Machine** (`web.archive.org/web/*/URL`) - profile snapshots, sometimes including removed posts and, historically, likes/activity pages.
- **Search-engine caches** - largely degraded now that Google retired its cache button, but other engines retain limited functionality.
- **Handle-history services** (e.g., `memory.lol` for X) - map current numeric IDs back to prior handles and vice versa.
- Pull the numeric ID *before* content disappears; it's your anchor for archive lookups afterward.

### Contact-import enumeration
Some mobile apps confirm whether a given email or phone maps to an account when you add it to a device's contacts and let the app "find friends." Powerful for tying a selector to an account, but **high-risk**: it can notify the target and can flag your account. Use a clean, single-contact device or emulator, understand the notification behavior for that specific app version, and never run it from an account you can't afford to lose.

---

## 🌐 Platform Notes

Platform sections are deliberately brief and principle-focused, because specifics rot fast. Where a technique depends on a URL pattern or endpoint, treat it as an example of the *approach*, not a guaranteed-working recipe.

### Meta (Facebook / Instagram / Threads)
The highest-value, highest-friction ecosystem. Meta has spent years dismantling the enumeration techniques that made Facebook Graph the crown jewel of OSINT, and continues to.
- **Real names** - Facebook is the platform where targets most often use their real identity, tied to employer, school, and location, making filtered name search viable when it fails elsewhere.
- **Numeric UIDs** are recoverable from profile page source and anchor deeper queries. Page, event, and group objects carry their own IDs; city/place IDs appear in place URLs.
- **URL-addressable profile sections** (about, work, education, friends, photos, check-ins) let you methodically walk a profile rather than trusting the default view to surface everything.
- **Selector confirmation** via the password-reset flow can confirm an email/phone maps to an account and may reveal a masked recovery selector. Run it logged-out, from non-attributable infrastructure - repeated attempts can flag the session or notify the account holder.
- **Threads** rides on Instagram credentials: same numeric ID as the paired Instagram account, so it's a free pivot, though many users never actively post there.
- **Instagram** requires login for essentially everything useful. Numeric user IDs and an info endpoint let you translate an ID back into a current handle after a rename. Dev-tools Network capture is the clean path to full-res media and exact (Unix) post timestamps.

### X (Twitter)
The API paywall (2023) gutted the third-party tooling ecosystem, but the native **search operators** are still the most powerful text-search primitives of any major platform. Learn them instead of the advanced-search GUI - operators are scriptable, documentable, and monitor-able.

| Operator | Effect |
| --- | --- |
| `from:handle` | Posts authored by the account |
| `to:handle` | Posts directed at the account (incoming - often more revealing than outgoing) |
| `@handle` | Mentions |
| `since:YYYY-MM-DD` / `until:YYYY-MM-DD` | Date bounding |
| `geocode:lat,long,Nkm` | Posts within radius N of coordinates (reliable radii: 1/5/10/25; `mi` also valid) |
| `filter:links` / `filter:replies` / `filter:media` | Content-type filters (negate with `-`) |
| `min_faves:N` / `min_replies:N` | Engagement thresholds |
| `url:domain.tld` | Posts linking to a domain |
| `"exact phrase"` … `term OR term` | Mandatory phrase + optional terms (OR must be uppercase) |

Combine operators for surgical queries and to page through years of history one interval at a time when the profile timeline won't scroll far enough back. Geo-tagged posts are now rare (location defaults to off), so a null geo result rules out nothing. For deleted/renamed accounts, use archives plus `memory.lol` for handle history. `OldTweetDeck` restores much of the retired TweetDeck monitoring workflow for live column-based tracking.

### TikTok
Now a primary source for targets under ~30, and frequently where a target who locked down everything else is still posting publicly under the same handle.
- **URL-addressable** profiles, tag pages, user search, and video search - many accessible without login, some gated.
- Three source-code identifiers per profile: numeric `id`, `uniqueId` (handle), and `nickname` (non-unique vanity string). The numeric ID is your stable anchor.
- **`yt-dlp` is the right tool** for pulling videos plus a rich platform-generated metadata JSON (upload date/time, view/like/comment counts, codecs, dimensions, channel IDs) - far more defensible than native right-click save.
- Exact upload time is recoverable from a Unix timestamp in page source when you need precision beyond the displayed date.
- Comments are reachable as JSON via the Network tab (`comment/list` endpoint) for structured export.

### LinkedIn
Underused in social OSINT and invaluable for **corporate reconnaissance and pretext development**: org charts, tenure, tooling and tech-stack mentions in job posts, reporting lines, and employee enumeration. Aggressive against logged-in scraping and profile-view notifications - mind your research account and never view a target while logged into an attributable profile. Google dorking (`site:linkedin.com/in "Company" "Title"`) surfaces profiles without tripping in-platform view alerts.

### Reddit
Pseudonymous but often startlingly self-documenting. A single username maps to a complete post/comment history via `reddit.com/user/handle`. Public API and third-party tools expose per-user activity aggregation - subreddit participation, active hours (timezone inference), recurring topics, and self-disclosures. Reddit handles are prime candidates for cross-platform pivots. Pushshift-style historical corpora (availability varies) recover deleted/edited comments.

### The Fediverse & Bluesky
Platform migration is an intelligence opportunity: displaced users recreate accounts under familiar handles.
- **Bluesky** (`bsky.app`) - federated, open, easy to search; popular with technical audiences. Low friction to investigate.
- **Mastodon** / the wider fediverse - instance-fragmented, so search is per-instance; `site:` dorking across common instances helps locate accounts.
- **Threads** - see Meta above.

Pivot known handles here whenever a target's primary platform activity drops off.

### Snapchat / Telegram / Discord
- **Snapchat** - ephemeral by design; primary public surfaces are Snap Map (geolocated public stories) and the Spotlight feed. Little persistent public footprint.
- **Telegram** - public channel/group content is broadly searchable and a major venue for leaked/breach data; treat channel names and forwarded-message provenance as selectors. Handle any breach material per your engagement's data-handling policy; see breach tooling (H8mail, Intelligence X, LeakLookup) in [OSINT_TOOLS_CATALOG.md](OSINT_TOOLS_CATALOG.md).
- **Discord** - largely closed; public intelligence is limited to invite-linked public servers and third-party server directories. Membership enumeration generally requires being in the server.

---

## 🗄️ Evidence Handling

If collection might support a report, a client deliverable, or legal process, capture it so a third party can trust it.

- **Capture from the source.** Prefer dev-tools/native capture over third-party downloaders you can't attest to. You should be able to describe exactly how each artifact was obtained.
- **Record provenance for every artifact:** full URL, numeric account ID, collection date/time (with timezone), and the account/infrastructure used to collect.
- **Preserve timestamps.** Convert and record platform Unix timestamps to a documented standard (UTC), and note the display value you saw alongside the precise value.
- **Hash media** on acquisition (SHA-256) and record the hash so integrity is provable later.
- **Screenshot *and* save source/media.** A screenshot shows context; the saved file and its metadata prove content. Keep both.
- **Don't alter accounts.** Any like, follow, or comment you leave is both an OPSEC failure and a contamination of the evidentiary record.

---

## Related Files
- [README.md](README.md) - OSINT section index (contains the Legal, Ethical & OPSEC framework)
- [OSINT_GUIDE.md](OSINT_GUIDE.md) - Master OSINT methodology guide
- [OSINT_CHEATSHEET.md](OSINT_CHEATSHEET.md) - Quick command reference
- [OSINT_TOOLS_CATALOG.md](OSINT_TOOLS_CATALOG.md) - Full tool catalog and API configuration
- [Playbook/README.md](Playbook/README.md) - OSINT Investigator Playbook that orchestrates these tools
- [../Tradecraft/osint-threat-intel.md](../Tradecraft/osint-threat-intel.md) - Advanced OSINT and threat intelligence techniques

---

*This document covers publicly available information collection during authorized engagements only. See the Legal & Ethical Notice in the [OSINT section README](README.md) and the [Tradecraft](../Tradecraft/osint-threat-intel.md) guide for scope, authorization, and OPSEC requirements.*

## 📚 Further Reading
- Michael Bazzell, *Open Source Intelligence Techniques* - the standard reference for platform-by-platform social media collection; his `inteltechniques.com/tools` offline suite automates much of the URL construction described above. Treat any specific technique in print as a snapshot in time.
- [OSINT Framework](https://osintframework.com/) - curated tool directory.
- [Bellingcat's Online Investigation Toolkit](https://bit.ly/bcattools) - practitioner-maintained.
