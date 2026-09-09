# LeakLens Open Security Registry

Public data repository maintained by [LeakLens](https://leaklens.org) — an independent, non-commercial project.

The LeakLens Registry is an open, auditable dataset tracking documented data breach exposures, along with aggregated CVE and open-source supply-chain vulnerability data. Every entry is labeled by verification status (confirmed / disputed / unconfirmed) — this project does not treat every claim as fact.

---

## Features and Capabilities

- **Breach Verification Tracking**: Records of documented data exposures, each labeled by verification status and linked to its original source — not published as "confirmed" without one.
- **CVE and Vulnerability Feeds**: Aggregated feed of CVEs, CISA KEV-cataloged exploits, and open-source package advisories, pulled from upstream sources rather than independently assessed.
- **Open JSON Data Feeds**: Machine-readable feeds intended for use by security researchers, auditors, and other tools — not just the LeakLens site itself.
- **Scheduled Sync**: Periodic aggregation across NIST NVD API 2.0, CISA KEV, GitHub Security Advisories, and OSV databases.

---

## Open Data Feeds

| Data Feed | Location | Format | Description |
|-----------|----------|--------|-------------|
| Data Breach Registry | [`leaks.json`](leaks.json) | JSON | Documented breach exposures, with source and verification status per entry |
| CVE Master Index | [`CVE/cves_index.json`](CVE/cves_index.json) | JSON | Index of vulnerabilities, CVSS scores, and threat levels, as reported upstream |
| Paginated CVE Feed | [`CVE/cves_page_1.json`](CVE/cves_page_1.json) | JSON | Paginated CVE feed, 50 items per page |
| Malicious Packages Feed | [`CVE/malicious_packages.json`](CVE/malicious_packages.json) | JSON | Open-source supply-chain attacks: malicious npm/pypi packages with preinstall hooks, dependency confusion, credential exfiltration, or remote code execution payloads |

---

## Data Integrity Approach

This project tries to hold a clear line between "someone claimed this" and "this is independently verified" — most breach coverage doesn't, and that gap is part of why this registry exists.

1. **Verification labeling**: Every breach entry is marked `confirmed`, `disputed`, or `unconfirmed`. Nothing is published as confirmed without a traceable public source or an official disclosure.
2. **Source attribution**: Every entry links to where the information came from. Entries without a locatable source are not published to the main feed.
3. **Schema compliance**: Breach records follow `schema.json`; vulnerability entries carry standard CVSS/CWE metadata as provided by upstream sources.
4. **Open to correction**: Anyone can inspect, audit, or fork this registry. To flag an error or submit a disclosure, open a Pull Request or an issue.

This is a best-effort, independently-run project, not a certification body — treat "confirmed" here as "independently corroborated as of the listed date," and always check the linked source yourself for anything decision-relevant.

---

## About LeakLens

LeakLens is an independent, non-commercial registry built for transparency around data breaches and infrastructure vulnerabilities — not a company, and not a security vendor.

- Website: [leaklens.org](https://leaklens.org)
- GitHub: [github.com/leak-lens](https://github.com/leak-lens)
- License: Data provided under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Attribution required.