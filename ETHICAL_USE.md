# Ethical use

This tool is intended for **defensive, authorised assessment only**. It exists
because incident-response teams and consultants need a reproducible way to ask
"have any of our org's credentials shown up in a public breach corpus" without
manually stitching three separate APIs together every time.

## What the tool does

* Queries the HaveIBeenPwned **Pwned Passwords** k-anonymity endpoint
  (`https://api.pwnedpasswords.com/range/{prefix}`). No account is named to
  HIBP — only the first five hex characters of the SHA-1 hash leave the
  machine. This is the same protocol the HIBP browser extension uses.
* Optionally queries the HIBP **Breached-Accounts** endpoint
  (`https://haveibeenpwned.com/api/v3/breachedaccount/{account}`) when an API
  key is configured. The endpoint is rate-limited at one request per 1.5
  seconds per HIBP's published terms; this tool sleeps between calls.
* Optionally runs read-only GitHub code-search dork queries
  (`"<domain>" filename:.env`, `"<domain>" password`, etc.) when a
  `GITHUB_TOKEN` is set. This is the same surface a defender can already see
  by visiting github.com/search.
* Cross-references a **local synthetic CSV** of breach records (in
  `tests/fixtures/sample_breach_data.csv`) — every row is fake and clearly
  labelled. The tool does **not** ship real breach data.

## What the tool does not do

* It does **not** perform authentication probes, credential stuffing, password
  spraying, or any active testing against any service.
* It does **not** attempt to crack hashes or de-anonymise breach records.
* It does **not** create accounts on any platform.
* It does **not** scrape paste sites, dark-web markets, or any other source
  that requires impersonating a non-defensive party.
* It does **not** retain credentials. The k-anonymity protocol means HIBP
  never sees the password. The only thing written to disk is the structured
  finding (e.g., "the SHA-1 of this candidate password appears in N public
  breaches").

## Authorised use only

By using this software you affirm that:

1. You are scanning a domain you own, or a domain whose owner has provided
   written authorisation (an engagement letter, a SoW, or equivalent).
2. You will not use the tool to dox, harass, or otherwise target individuals.
3. You will respect the rate limits of every upstream service. The tool
   already enforces these — do not patch them out.
4. If you redistribute the tool, you keep this file in the repository and
   carry the same restrictions through.

This software is provided as-is under the MIT license. The license does not
override the ethical and legal expectations above; the two stand together.
