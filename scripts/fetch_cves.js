#!/usr/bin/env node
/**
 * LeakLens Registry — CVE Data Fetcher
 * Pulls from:
 *   1. CIRCL CVE Search API (cve.circl.lu) — recent CVEs
 *   2. CISA KEV Catalog — known exploited vulnerabilities
 *   3. GitHub Advisory DB (OSV format) — package advisories
 *
 * Output: /CVE/cves_index.json + /CVE/cves_page_N.json + /CVE/malicious_packages.json
 * Usage: node scripts/fetch_cves.js
 */

const https = require("https");
const fs = require("fs");
const path = require("path");

const OUT_DIR = path.join(__dirname, "..", "CVE");
const PAGE_SIZE = 50;

// ── helpers ──────────────────────────────────────────────────────────────────

function get(url) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, { headers: { "User-Agent": "LeakLens-Registry/1.0" } }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        return resolve(get(res.headers.location));
      }
      let data = "";
      res.on("data", (chunk) => (data += chunk));
      res.on("end", () => {
        try {
          resolve(JSON.parse(data));
        } catch (e) {
          reject(new Error(`JSON parse error for ${url}: ${e.message}`));
        }
      });
    });
    req.on("error", reject);
    req.setTimeout(30000, () => { req.destroy(); reject(new Error(`Timeout: ${url}`)); });
  });
}

function severityFromCvss(score) {
  if (score === null || score === undefined) return null;
  if (score >= 9.0) return "Critical";
  if (score >= 7.0) return "High";
  if (score >= 4.0) return "Medium";
  return "Low";
}

/**
 * Extract CVSS base score from a vector string.
 * Works for both CVSS v3.1 vectors (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
 * and CVSS v2 vectors without version prefix (AV:N/AC:L/Au:N/C:H/I:H/A:H).
 * Returns null if vector cannot be parsed.
 */
function extractCvssFromVector(vector) {
  if (!vector || typeof vector !== "string") return null;

  // Common mappings
  const impactMap = { H: 0.56, L: 0.22, P: 0.22, N: 0 };
  const exploitabilityMap = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }; // AV for v3
  const accessComplexityMap = { L: 0.77, H: 0.44 }; // AC for v3
  const authMap = { N: 0.85, L: 0.62, H: 0.27 }; // PR for v3
  const uiMap = { N: 0.85, R: 0.62 }; // UI for v3

  // Extract CVSS v3 fields
  const cMatch = vector.match(/C:([HILP]?\d?)/);
  const iMatch = vector.match(/I:([HILP]?\d?)/);
  const aMatch = vector.match(/A:([HILP]?\d?)/);
  const avMatch = vector.match(/AV:(N|A|L|P)/);
  const acMatch = vector.match(/AC:(L|H)/);
  const prMatch = vector.match(/PR:(N|L|H)/);
  const uiMatch = vector.match(/UI:(N|R)/);
  const sMatch = vector.match(/S:(U|C)/);

  // Extract CVSS v2 fields (fallback)
  const v2AvMatch = vector.match(/AV:(N|A|L|P)/);
  const v2AcMatch = vector.match(/AC:(N|L|H)/);
  const v2AuMatch = vector.match(/Au:(N|S|M)/);
  const v2CMatch = vector.match(/C:([HILP]?\d?)/);
  const v2IMatch = vector.match(/I:([HILP]?\d?)/);
  const v2AMatch = vector.match(/A:([HILP]?\d?)/);

  // If CVSS v3 fields present, use v3 calculation
  if (cMatch && iMatch && aMatch && avMatch && acMatch && prMatch && uiMatch && sMatch) {
    const cVal = impactMap[cMatch[1]] || 0;
    const iVal = impactMap[iMatch[1]] || 0;
    const aVal = impactMap[aMatch[1]] || 0;
    const avVal = exploitabilityMap[avMatch[1]] || 0.85;
    const acVal = accessComplexityMap[acMatch[1]] || 0.77;
    const isPrivRequired = prMatch[1] === "R";
    const prVal = (isPrivRequired ? authMap : { N: 0.85, L: 0.62, H: 0.27 })[prMatch[1]] || 0.85;
    const uiVal = uiMap[uiMatch[1]] || 0.85;
    const scopeChanged = sMatch[1] === "C";

    const impactSubScore = 1 - (1 - cVal) * (1 - iVal) * (1 - aVal);
    if (impactSubScore <= 0) return null;

    const impact = scopeChanged
      ? 7.52 * (impactSubScore - 0.029) - 3.25 * Math.pow(impactSubScore - 0.02, 15)
      : 6.42 * impactSubScore;

    const exploitability = 8.22 * avVal * acVal * prVal * uiVal;

    let baseScore;
    if (scopeChanged) {
      baseScore = Math.min(1.08 * (impact + exploitability), 10);
    } else {
      baseScore = impact + exploitability;
    }

    if (baseScore <= 0) return null;
    return Math.round(baseScore * 10) / 10;
  }

  // Fallback to CVSS v2 calculation (for older CVE without v3 vector)
  const avVal2 = exploitabilityMap[v2AvMatch?.[1]] || 0.85;
  const acVal2 = { N: 0.71, L: 0.56, H: 0.22 }[v2AcMatch?.[1]] || 0.56;
  const auVal2 = { N: 0.704, S: 0.56, M: 0.22 }[v2AuMatch?.[1]] || 0.56;

  const cVal2 = impactMap[v2CMatch?.[1]] || 0;
  const iVal2 = impactMap[v2IMatch?.[1]] || 0;
  const aVal2 = impactMap[v2AMatch?.[1]] || 0;

  if (avVal2 === 0 || acVal2 === 0 || auVal2 === 0) return null;

  // CVSS v2 formula
  const exploitability2 = 20 * avVal2 * acVal2 * auVal2;
  const impact2 = 10.41 * (1 - (1 - cVal2) * (1 - iVal2) * (1 - aVal2));

  let baseScore2;
  const sum = impact2 + exploitability2;
  if (sum >= 10) {
    baseScore2 = 10;
  } else if (impact2 <= 0) {
    baseScore2 = 0;
  } else {
    baseScore2 = Math.ceil(sum * 10) / 10;
  }

  return baseScore2;
}

function extractCvssScore(item) {
  if (typeof item.cvss === "number" && item.cvss > 0) return item.cvss;
  if (item.cvss && typeof item.cvss.score === "number" && item.cvss.score > 0) return item.cvss.score;
  if (typeof item.cvss3 === "number" && item.cvss3 > 0) return item.cvss3;
  if (typeof item.cvss_score === "number" && item.cvss_score > 0) return item.cvss_score;

  // GitHub Advisory API cvss_severities (v3 and v4)
  if (item.cvss_severities) {
    const v3 = item.cvss_severities.cvss_v3;
    if (v3 && typeof v3.score === "number" && v3.score > 0) return v3.score;
    const v4 = item.cvss_severities.cvss_v4;
    if (v4 && typeof v4.score === "number" && v4.score > 0) return v4.score;
  }

  // NVD metrics v3.1 / v3.0 / v2
  const v31 = item.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore;
  if (typeof v31 === "number") return v31;
  const v30 = item.metrics?.cvssMetricV30?.[0]?.cvssData?.baseScore;
  if (typeof v30 === "number") return v30;
  const v2 = item.metrics?.cvssMetricV2?.[0]?.cvssData?.baseScore;
  if (typeof v2 === "number") return v2;

  if (Array.isArray(item.severity)) {
    for (const s of item.severity) {
      if (s.type === "CVSS_V3" || s.type === "CVSS_V2") {
        const match = extractCvssFromVector(s.score);
        if (match) return match;
      }
    }
  }
  if (Array.isArray(item.scores)) {
    const s = item.scores[0];
    if (s?.cvss_v3?.baseScore) return s.cvss_v3.baseScore;
    if (s?.cvss_v2?.baseScore) return s.cvss_v2.baseScore;
  }
  return null;
}

function extractSeverity(item, cvssScore) {
  const fromScore = severityFromCvss(cvssScore);
  if (fromScore) return fromScore;

  // GitHub Advisory API cvss_severities text labels
  if (item.cvss_severities) {
    const v3 = item.cvss_severities.cvss_v3;
    if (v3 && typeof v3.severity === "string" && v3.severity.trim().length > 0) {
      const upper = v3.severity.trim().toUpperCase();
      if (upper === "CRITICAL") return "Critical";
      if (upper === "HIGH") return "High";
      if (upper === "MODERATE" || upper === "MEDIUM") return "Medium";
      if (upper === "LOW") return "Low";
    }
  }

  // Check string severity representations (GHSA / NVD / OSV)
  const candidates = [
    typeof item.severity === "string" ? item.severity : null,
    item.database_specific?.severity,
    item.metrics?.cvssMetricV31?.[0]?.cvssData?.baseSeverity,
    item.metrics?.cvssMetricV30?.[0]?.cvssData?.baseSeverity,
    item.metrics?.cvssMetricV2?.[0]?.cvssData?.baseSeverity,
  ];

  for (const c of candidates) {
    if (typeof c === "string" && c.trim().length > 0) {
      const upper = c.trim().toUpperCase();
      if (upper === "CRITICAL") return "Critical";
      if (upper === "HIGH") return "High";
      if (upper === "MODERATE" || upper === "MEDIUM") return "Medium";
      if (upper === "LOW") return "Low";
    }
  }
  return "Unknown";
}

function extractId(item) {
  if (Array.isArray(item.aliases)) {
    const cve = item.aliases.find((a) => typeof a === "string" && /^CVE-\d{4}-\d+$/i.test(a));
    if (cve) return cve.toUpperCase();
    const ghsa = item.aliases.find((a) => typeof a === "string" && /^GHSA-[a-z0-9-]+$/i.test(a));
    if (ghsa) return ghsa.toUpperCase();
    const mal = item.aliases.find((a) => typeof a === "string" && /^MAL-\d{4}-\d+$/i.test(a));
    if (mal) return mal.toUpperCase();
  }
  if (typeof item.id === "string" && (/^CVE-\d{4}-\d+$/i.test(item.id) || /^GHSA-[a-z0-9-]+$/i.test(item.id) || /^MAL-\d{4}-\d+$/i.test(item.id))) {
    return item.id.toUpperCase();
  }
  if (typeof item.cve_id === "string" && /^CVE-\d{4}-\d+$/i.test(item.cve_id)) {
    return item.cve_id.toUpperCase();
  }
  return null;
}

function extractProducts(item) {
  const products = [];
  if (Array.isArray(item.vulnerabilities)) {
    for (const v of item.vulnerabilities) {
      if (v.package?.name) {
        products.push(`${v.package.name} ${v.package.ecosystem || ""}`.trim());
      }
    }
  }
  if (Array.isArray(item.affected)) {
    for (const a of item.affected) {
      if (a.package?.name) {
        products.push(`${a.package.name} ${a.package.ecosystem || ""}`.trim());
      }
    }
  }
  if (Array.isArray(item.vulnerable_configuration)) {
    for (const c of item.vulnerable_configuration) {
      const parts = c.split(":");
      if (parts[4]) products.push(`${parts[3]} ${parts[4]}`.trim());
    }
  }
  if (Array.isArray(item.configurations?.nodes)) {
    for (const node of item.configurations.nodes) {
      for (const match of node.cpeMatch || []) {
        const parts = (match.criteria || "").split(":");
        if (parts[4]) products.push(`${parts[3]} ${parts[4]}`.trim());
      }
    }
  }
  return Array.from(new Set(products)).slice(0, 5);
}

function cleanSummary(text) {
  if (typeof text !== "string") return text;
  return text
    .replace(/^---\s*/gm, "")
    .replace(/_=-\s*Per source details\..*?=-_/gs, "")
    .replace(/^##\s*Source:.*$/gm, "")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

function extractSummary(item) {
  if (Array.isArray(item.descriptions)) {
    const enDesc = item.descriptions.find((d) => d.lang === "en" || d.lang === "en-US")?.value || item.descriptions[0]?.value;
    if (typeof enDesc === "string" && enDesc.trim().length > 10) {
      return cleanSummary(enDesc);
    }
  }

  const candidates = [
    item.details,
    item.description,
    item.summary,
    item.overview,
    item.containers?.cna?.descriptions?.[0]?.value,
    item.document?.notes?.[0]?.text,
    item.document?.title,
  ];

  let best = "";
  for (const c of candidates) {
    if (typeof c === "string" && c.trim().length > 10) {
      const cleaned = cleanSummary(c);
      if (cleaned.length > best.length) {
        best = cleaned;
      }
    }
  }
  if (best.length > 10) return best;

  if (item.summary && typeof item.summary === "string" && item.summary.trim().length > 5) {
    return cleanSummary(item.summary);
  }

  return "Security disclosure registered in public vulnerability database.";
}

function extractCwe(item) {
  if (typeof item.cwe === "string") return item.cwe;
  if (Array.isArray(item.cwes) && item.cwes[0]) return item.cwes[0];
  if (item.containers?.cna?.problemTypes?.[0]?.descriptions?.[0]?.cweId) {
    return item.containers.cna.problemTypes[0].descriptions[0].cweId;
  }
  if (Array.isArray(item.weaknesses)) {
    for (const w of item.weaknesses) {
      const desc = w.description?.[0]?.value || w.description;
      if (typeof desc === "string" && /^CWE-\d+/i.test(desc)) return desc.toUpperCase();
    }
  }
  return null;
}

function extractReferences(item) {
  if (Array.isArray(item.references)) {
    return item.references
      .map((r) => (typeof r === "string" ? r : r?.url))
      .filter(Boolean)
      .slice(0, 5);
  }
  if (Array.isArray(item.refurls)) return item.refurls.slice(0, 5);
  return [];
}

function extractDate(item) {
  const raw = item.published || item.publishedDate || item.created_at || item.published_at || item.Published;
  if (!raw) return null;
  const d = new Date(raw);
  if (isNaN(d.getTime())) return null;
  return d.toISOString().slice(0, 10);
}

function normalise(item, exploitedIds = new Set()) {
  const id = extractId(item);
  if (!id) return null;

  const cvssScore = extractCvssScore(item);
  const severity = extractSeverity(item, cvssScore);

  return {
    id,
    summary: extractSummary(item),
    cvssScore,
    severity,
    published: extractDate(item),
    modified: (item.modified || item.lastModifiedDate || item.updated_at)
      ? new Date(item.modified || item.lastModifiedDate || item.updated_at).toISOString().slice(0, 10)
      : null,
    cwe: extractCwe(item),
    references: extractReferences(item),
    vulnerableProducts: extractProducts(item),
    isExploited: exploitedIds.has(id) || Boolean(item.isExploited),
  };
}

// ── sources ───────────────────────────────────────────────────────────────────

async function fetchCisaKev() {
  console.log("  → Fetching CISA KEV catalog...");
  try {
    const data = await get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json");
    const ids = new Set((data.vulnerabilities || []).map((v) => v.cveID));
    console.log(`     CISA KEV: ${ids.size} exploited CVEs`);
    return ids;
  } catch (e) {
    console.warn("     CISA KEV failed:", e.message);
    return new Set();
  }
}

async function fetchGithubAdvisories(exploitedIds) {
  console.log("  → Fetching OSV / GitHub Advisory DB...");
  const results = [];
  const ecosystems = [
    "npm", "PyPI", "Go", "Maven", "RubyGems", "NuGet",
    "Linux", "Packagist", "crates.io", "Hex", "Android", "Pub"
  ];
  for (const eco of ecosystems) {
    try {
      const data = await get(`https://api.osv.dev/v1/query_batch?ecosystem=${encodeURIComponent(eco)}&page_size=100`);
      if (Array.isArray(data.vulns)) {
        for (const v of data.vulns) {
          const norm = normalise(v, exploitedIds);
          if (norm) results.push(norm);
        }
      }
      await new Promise((r) => setTimeout(r, 150));
    } catch (e) {
      console.warn(`     OSV ${eco} failed:`, e.message);
    }
  }
  console.log(`     OSV Database: ${results.length} records`);
  return results;
}

async function fetchGithubAdvisoriesApi(exploitedIds) {
  console.log("  → Fetching GitHub Security Advisories API...");
  const results = [];
  try {
    const data = await get("https://api.github.com/advisories?per_page=100");
    if (Array.isArray(data)) {
      for (const item of data) {
        const norm = normalise(item, exploitedIds);
        if (norm) results.push(norm);
      }
    }
    console.log(`     GitHub Advisories API: ${results.length} records`);
  } catch (e) {
    console.warn("     GitHub Advisories API skipped:", e.message);
  }
  return results;
}

/** Fetch NVD CVEs with pagination, retry on rate limit, and stop on consecutive empty pages */
async function fetchNvdCves(exploitedIds) {
  console.log("  → Fetching NIST NVD API 2.0 (paginated, with retry)...");
  const results = [];
  const PAGE_SIZE = 100;
  let startIndex = 0;
  let consecutiveEmpty = 0;
  const MAX_CONSECUTIVE_EMPTY = 3;
  const MAX_TOTAL_RECORDS = 10000;

  for (let page = 1; ; page++) {
    const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=${PAGE_SIZE}&startIndex=${startIndex}`;
    let data;
    try {
      data = await get(url);
    } catch (e) {
      if (e.message.includes("error code: 1015") || e.message.includes("rate limit")) {
        console.warn(`     NIST NVD: rate limit hit at page ${page} (${results.length} records) — waiting 6s...`);
        await new Promise((r) => setTimeout(r, 6000));
        continue;
      }
      console.warn(`     NIST NVD: error at page ${page}:`, e.message);
      break;
    }

    const vulnerabilities = data.vulnerabilities || [];
    if (vulnerabilities.length === 0) {
      consecutiveEmpty++;
      if (consecutiveEmpty >= MAX_CONSECUTIVE_EMPTY) {
        console.log(`     NIST NVD: ${consecutiveEmpty} consecutive empty pages — stopping`);
        break;
      }
      console.log(`     NIST NVD page ${page}: empty (consecutive ${consecutiveEmpty})`);
      startIndex += PAGE_SIZE;
      continue;
    }
    consecutiveEmpty = 0;

    for (const item of vulnerabilities) {
      const cveObj = item.cve;
      if (!cveObj) continue;
      const norm = normalise(cveObj, exploitedIds);
      if (norm) results.push(norm);
    }
    startIndex += PAGE_SIZE;
    console.log(`     NIST NVD page ${page}: +${vulnerabilities.length} records (total ${results.length})`);

    if (results.length >= MAX_TOTAL_RECORDS) {
      console.log(`     NIST NVD: reached max ${MAX_TOTAL_RECORDS} records`);
      break;
    }
  }

  console.log(`     NIST NVD: ${results.length} records fetched`);
  return results;
}

async function fetchCirclCves(exploitedIds) {
  console.log("  → Fetching CIRCL CVE Search (recent)...");
  const results = [];
  try {
    const data = await get("https://cve.circl.lu/api/last/100");
    if (Array.isArray(data)) {
      for (const item of data) {
        const norm = normalise(item, exploitedIds);
        if (norm) results.push(norm);
      }
    }
    console.log(`     CIRCL: ${results.length} records`);
  } catch (e) {
    console.warn("     CIRCL failed:", e.message);
  }
  return results;
}

function loadExistingCves() {
  const existingMap = new Map();
  if (!fs.existsSync(OUT_DIR)) return existingMap;

  const files = fs.readdirSync(OUT_DIR);
  for (const file of files) {
    if (/^cves_page_\d+\.json$/.test(file)) {
      try {
        const filePath = path.join(OUT_DIR, file);
        const data = JSON.parse(fs.readFileSync(filePath, "utf8"));
        if (Array.isArray(data.cves)) {
          for (const item of data.cves) {
            if (item && item.id && item.id !== "CVE-DISCLOSURE") {
              existingMap.set(item.id.toUpperCase(), item);
            }
          }
        }
      } catch (e) {
        console.warn(`     Warning: failed to read ${file}: ${e.message}`);
      }
    }
  }
  console.log(`  → Loaded ${existingMap.size} accumulated CVEs from local storage`);
  return existingMap;
}

// ── main ──────────────────────────────────────────────────────────────────────

async function main() {
  console.log("\n🔍 LeakLens Registry — CVE Fetcher & Accumulator\n");

  const existingMap = loadExistingCves();
  const exploitedIds = await fetchCisaKev();

  const [ghAdvisories, ghApi, nvdCves, circlCves] = await Promise.all([
    fetchGithubAdvisories(exploitedIds),
    fetchGithubAdvisoriesApi(exploitedIds),
    fetchNvdCves(exploitedIds),
    fetchCirclCves(exploitedIds),
  ]);

  // Accumulate and merge: add new CVEs, update existing ones without losing data
  for (const item of [...ghAdvisories, ...ghApi, ...nvdCves, ...circlCves]) {
    if (!item || !item.id || item.id === "CVE-DISCLOSURE") continue;
    const key = item.id.toUpperCase();
    const existing = existingMap.get(key);
    if (!existing) {
      existingMap.set(key, item);
    } else {
      const bestSummary = (item.summary && item.summary !== "Security disclosure registered in public vulnerability database." && item.summary.length >= (existing.summary?.length || 0))
        ? item.summary
        : existing.summary;
      const bestCvss = item.cvssScore !== null ? item.cvssScore : existing.cvssScore;
      const bestSeverity = (item.severity && item.severity !== "Unknown") ? item.severity : existing.severity;
      const bestCwe = item.cwe || existing.cwe;
      const bestProducts = (Array.isArray(item.vulnerableProducts) && item.vulnerableProducts.length > 0) ? item.vulnerableProducts : (existing.vulnerableProducts || []);

      existingMap.set(key, {
        ...existing,
        ...item,
        summary: bestSummary,
        cvssScore: bestCvss,
        severity: bestSeverity,
        cwe: bestCwe,
        vulnerableProducts: bestProducts,
        isExploited: existing.isExploited || item.isExploited,
      });
    }
  }

  const all = Array.from(existingMap.values());

  // Cross-reference KEV: mark isExploited for any CVE that matches the KEV catalog
  let kevMatches = 0;
  for (const cve of all) {
    if (exploitedIds.has(cve.id)) {
      cve.isExploited = true;
      kevMatches++;
    }
  }
  if (kevMatches > 0) {
    console.log(`   🔗 KEV cross-reference: ${kevMatches} CVEs now marked as exploited`);
  }

  // Separate MAL-* from standard CVEs for cleaner feed
  const standardCves = all.filter((c) => c.id.startsWith("CVE-") || c.id.startsWith("GHSA-"));
  const maliciousPkgs = all.filter((c) => c.id.startsWith("MAL-"));

  console.log(`\n✅ Total accumulated: ${all.length} entries`);
  console.log(`   Standard CVEs: ${standardCves.length}`);
  console.log(`   Malicious packages: ${maliciousPkgs.length}`);

  if (!fs.existsSync(OUT_DIR)) fs.mkdirSync(OUT_DIR, { recursive: true });

  const today = new Date().toISOString().slice(0, 10);
  const pages = [];

  // Write standard CVE pages (excludes MAL-* malicious packages)
  for (let i = 0; i < standardCves.length; i += PAGE_SIZE) {
    const pageNum = Math.floor(i / PAGE_SIZE) + 1;
    const chunk = standardCves.slice(i, i + PAGE_SIZE);
    const filename = `cves_page_${pageNum}.json`;
    const pageData = {
      version: "1.0",
      lastUpdated: today,
      source: "CIRCL CVE Search + GitHub Advisory OSV + CISA KEV + NIST NVD",
      pagination: {
        page: pageNum,
        pageSize: PAGE_SIZE,
        totalPages: Math.ceil(standardCves.length / PAGE_SIZE),
        totalItems: standardCves.length,
        hasNextPage: i + PAGE_SIZE < standardCves.length,
        hasPrevPage: pageNum > 1,
      },
      cves: chunk,
    };
    fs.writeFileSync(path.join(OUT_DIR, filename), JSON.stringify(pageData, null, 2));
    pages.push({ page: pageNum, file: filename, count: chunk.length });
    console.log(`   📄 ${filename}: ${chunk.length} CVEs`);
  }

  // Write malicious packages feed (separate file)
  if (maliciousPkgs.length > 0) {
    const malFilename = `malicious_packages.json`;
    const malData = {
      version: "1.0",
      lastUpdated: today,
      source: "GitHub Advisory OSV + GitHub Advisory API (malicious package detection)",
      description: "Open-source supply-chain attacks: malicious npm/pypi packages with preinstall hooks, dependency confusion, credential exfiltration, or remote code execution payloads.",
      pagination: {
        page: 1,
        pageSize: maliciousPkgs.length,
        totalItems: maliciousPkgs.length,
      },
      maliciousPackages: maliciousPkgs,
    };
    fs.writeFileSync(path.join(OUT_DIR, malFilename), JSON.stringify(malData, null, 2));
    console.log(`   📄 ${malFilename}: ${maliciousPkgs.length} malicious packages`);
  }

  const index = {
    version: "1.0",
    lastUpdated: today,
    source: "CIRCL CVE Search + GitHub Advisory OSV + CISA KEV + NIST NVD",
    meta: {
      total: all.length,
      cves: standardCves.length,
      maliciousPackages: maliciousPkgs.length,
      exploited: standardCves.filter((c) => c.isExploited).length,
      kevCatalogSize: exploitedIds.size,
      pageSize: PAGE_SIZE,
      totalPages: pages.length,
    },
    pages,
  };
  fs.writeFileSync(path.join(OUT_DIR, "cves_index.json"), JSON.stringify(index, null, 2));
  console.log(`\n✅ Written: CVE/cves_index.json + ${pages.length} accumulated page file(s)`);
  console.log(`   Exploited (CISA KEV): ${index.meta.exploited} / ${index.meta.total}\n`);
}

main().catch((e) => {
  console.error("Fatal:", e);
  process.exit(1);
});
