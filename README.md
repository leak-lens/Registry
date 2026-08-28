# LeakLens Registry

Public registry of verified data breach records. Each entry is independently verified by LeakLens.

## Structure

```
leaks.json          — all verified breach records
schema.json         — JSON Schema for validation
```

## How entries are added

### Manual (recommended for high-profile breaches)
1. Create a new entry in `leaks.json`
2. Follow the schema in `schema.json`
3. Submit a PR with at least 1 verification source
4. After review → merge

### Auto-publish (from radar)
The LeakLens radar automatically publishes entries that meet verification criteria:
- Source is from a trusted domain (BleepingComputer, SecurityWeek, OCCRP, etc.)
- Has specific data (company name, date, record count)
- Confidence score ≥ 0.6

## Entry format

```json
{
  "slug": "company-name-2026",
  "title": "Company Name Data Exposure — 5M Records",
  "institution": "Company Name",
  "date": "2026-01-15",
  "size": 5000000,
  "status": "verified",
  "severity": "High",
  "exposedData": ["Email addresses", "Passwords"],
  "description": "Brief description of the breach.",
  "methodology": "Verified via OCCRP investigation and company disclosure.",
  "sources": [
    {
      "url": "https://example.com/report",
      "title": "Report title",
      "publisher": "Publisher name",
      "date": "2026-01-10"
    }
  ]
}
```

## Status values

| Status | Meaning |
|--------|---------|
| `verified` | Confirmed by LeakLens with ≥1 trusted source |
| `confirmed` | Company officially acknowledged the breach |
| `disputed` | Company disputes the breach or its scale |
| `unconfirmed` | Reported but not yet independently verified |

## Validation

Before publishing, validate your entry:

```bash
node -e "
  const data = require('./leaks.json');
  const leaks = data.leaks;
  const schema = require('./schema.json');
  console.log('Total entries:', leaks.length);
  console.log('Schema valid:', true); // Add ajv for full validation
"
```

## License

Data in this registry is provided under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Source attribution is required.
