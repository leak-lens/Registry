#!/usr/bin/env node
/**
 * LeakLens Registry — CVE Data Fetcher
 * Pulls from:
 *   1. CIRCL CVE Search API (cve.circl.lu) — recent CVEs
 *   2. CISA KEV Catalog — known exploited vulnerabilities
 *   3. GitHub Advisory DB (OSV format) — package advisories
 *
 * Output: /CVE/cves_index.json + /CVE/cves_page_N.json
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
    req.setTimeout(10000, () => { req.destroy(); reject(new Error(`Timeout: ${url}`)); });
  });
}

function severityFromCvss(score) {
  if (score === null || score === undefined) return "Unknown";
  if (score >= 9.0) return "Critical";
  if (score >= 7.0) return "High";
  if (score >= 4.0) return "Medium";
  return "Low";
}

function extractCvssScore(item) {
  if (typeof item.cvss === "number" && item.cvss > 0) return item.cvss;
  if (item.cvss3 && typeof item.cvss3 === "number") return item.cvss3;
  if (Array.isArray(item.severity)) {
    for (const s of item.severity) {
      if (s.type === "CVSS_V3" || s.type === "CVSS_V2") {
        const match = s.score?.match(/\/(\d+\.\d+)$/);
        if (match) return parseFloat(match[1]);
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
  if (Array.isArray(item.affected)) {
    return item.affected
      .map((a) => `${a.package?.name || "unknown"} ${a.package?.ecosystem || ""}`.trim())
      .filter(Boolean)
      .slice(0, 5);
  }
  if (Array.isArray(item.vulnerable_configuration)) {
    return item.vulnerable_configuration.slice(0, 3).map((c) => {
      const parts = c.split(":");
      return parts[4] ? `${parts[3]} ${parts[4]}`.trim() : c;
    });
  }
  return [];
}

function cleanSummary(text) {
  if (typeof text !== "string") return text;
  return text
    .replace(/^---\s*/gm, "")
    .replace(/_-=\s*Per source details\..*?=-_/gs, "")
    .replace(/^##\s*Source:.*$/gm, "")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

function extractSummary(item) {
  const candidates = [
    item.details,
    item.summary,
    item.description,
    item.overview,
    item.containers?.cna?.descriptions?.[0]?.value,
    item.document?.notes?.[0]?.text,
    item.document?.title,
  ];
  for (const c of candidates) {
    if (typeof c === "string" && c.trim().length > 10) {
      const cleaned = cleanSummary(c);
      if (cleaned.length > 10) return cleaned;
    }
  }
  return "Security disclosure registered in public vulnerability database.";
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
  const raw = item.published || item.publishedDate || item.created_at || item.Published;
  if (!raw) return null;
  const d = new Date(raw);
  if (isNaN(d.getTime())) return null;
  return d.toISOString().slice(0, 10);
}

function normalise(item, exploitedIds = new Set()) {
  const id = extractId(item);
  if (!id) return null;

  const cvssScore = extractCvssScore(item);
  const severity = severityFromCvss(cvssScore);

  return {
    id,
    summary: extractSummary(item),
    cvssScore,
    severity,
    published: extractDate(item),
    modified: (item.modified || item.lastModifiedDate)
      ? new Date(item.modified || item.lastModifiedDate).toISOString().slice(0, 10)
      : null,
    cwe: item.cwe || item.containers?.cna?.problemTypes?.[0]?.descriptions?.[0]?.cweId || null,
    references: extractReferences(item),
    vulnerableProducts: extractProducts(item),
    isExploited: exploitedIds.has(id),
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
      const data = await get(`https://api.osv.dev/v1/query?ecosystem=${encodeURIComponent(eco)}&page_size=100`);
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

async function fetchNvdCves(exploitedIds) {
  console.log("  → Fetching NIST NVD API 2.0...");
  const results = [];
  try {
    const data = await get("https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=100");
    const vulnerabilities = data.vulnerabilities || [];
    for (const item of vulnerabilities) {
      const cveObj = item.cve;
      if (!cveObj) continue;
      const norm = normalise(cveObj, exploitedIds);
      if (norm) results.push(norm);
    }
    console.log(`     NIST NVD: ${results.length} records`);
  } catch (e) {
    console.warn("     NIST NVD skipped (rate limit or timeout):", e.message);
  }
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
      existingMap.set(key, {
        ...existing,
        ...item,
        isExploited: existing.isExploited || item.isExploited,
        summary: (item.summary && item.summary.length > (existing.summary?.length || 0)) ? item.summary : existing.summary,
      });
    }
  }

  const all = Array.from(existingMap.values());

  // Sort: exploited first, then CVSS desc
  all.sort((a, b) => {
    if (a.isExploited !== b.isExploited) return a.isExploited ? -1 : 1;
    return (b.cvssScore || 0) - (a.cvssScore || 0);
  });

  console.log(`\n✅ Total accumulated unique CVEs in database: ${all.length}`);

  if (!fs.existsSync(OUT_DIR)) fs.mkdirSync(OUT_DIR, { recursive: true });

  const today = new Date().toISOString().slice(0, 10);
  const pages = [];

  for (let i = 0; i < all.length; i += PAGE_SIZE) {
    const pageNum = Math.floor(i / PAGE_SIZE) + 1;
    const chunk = all.slice(i, i + PAGE_SIZE);
    const filename = `cves_page_${pageNum}.json`;
    const pageData = {
      version: "1.0",
      lastUpdated: today,
      source: "CIRCL CVE Search + GitHub Advisory OSV + CISA KEV + NIST NVD",
      pagination: {
        page: pageNum,
        pageSize: PAGE_SIZE,
        totalPages: Math.ceil(all.length / PAGE_SIZE),
        totalItems: all.length,
        hasNextPage: i + PAGE_SIZE < all.length,
        hasPrevPage: pageNum > 1,
      },
      cves: chunk,
    };
    fs.writeFileSync(path.join(OUT_DIR, filename), JSON.stringify(pageData, null, 2));
    pages.push({ page: pageNum, file: filename, count: chunk.length });
    console.log(`   📄 ${filename}: ${chunk.length} CVEs`);
  }

  const index = {
    version: "1.0",
    lastUpdated: today,
    source: "CIRCL CVE Search + GitHub Advisory OSV + CISA KEV + NIST NVD",
    meta: {
      total: all.length,
      exploited: all.filter((c) => c.isExploited).length,
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
