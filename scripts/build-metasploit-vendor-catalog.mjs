#!/usr/bin/env node
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { promisify } from 'node:util';

const METASPLOIT_METADATA_URL =
  'https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json';

const currentFile = fileURLToPath(import.meta.url);
const repoRoot = dirname(dirname(currentFile));
const dataDir = join(repoRoot, 'datasets');
const metasploitTitlesPath = join(dataDir, 'metasploit_exploit_titles.json');
const metasploitVendorsPath = join(dataDir, 'metasploit_vendor_products.json');
const kevPath = join(repoRoot, 'kev.json');
const historicPath = join(repoRoot, 'historic.json');

const args = new Set(process.argv.slice(2));

const log = (...messages) => {
  console.log('[metasploit-catalog]', ...messages);
};

const toArray = value => (Array.isArray(value) ? value : value ? [value] : []);

const normaliseCve = value => {
  if (!value) {
    return null;
  }
  const trimmed = value.trim();
  if (!trimmed) {
    return null;
  }
  const match = trimmed.match(/CVE[-_]?\s*(\d{4})[-_]?([0-9]{4,7})/i);
  if (!match) {
    return null;
  }
  return `CVE-${match[1]}-${match[2]}`;
};

const collectCves = references => {
  const seen = new Set();
  for (const reference of toArray(references)) {
    if (typeof reference !== 'string') {
      continue;
    }
    const cve = normaliseCve(reference);
    if (cve) {
      seen.add(cve);
    }
  }
  return [...seen];
};

const execFileAsync = promisify(execFile);

const fetchMetasploitMetadata = async () => {
  log('Downloading Metasploit metadata from Rapid7');
  try {
    const { stdout } = await execFileAsync('curl', ['-fsSL', METASPLOIT_METADATA_URL], {
      maxBuffer: 32 * 1024 * 1024
    });
    return JSON.parse(stdout);
  } catch (error) {
    const message = error?.stderr?.toString()?.trim() || error?.message || 'Unknown error';
    throw new Error(`Failed to download Metasploit metadata: ${message}`);
  }
};

const buildMetasploitTitles = metadata => {
  const entries = [];
  for (const value of Object.values(metadata)) {
    if (!value || typeof value !== 'object') {
      continue;
    }
    if ((value.type ?? '').toLowerCase() !== 'exploit') {
      continue;
    }
    const modulePath = typeof value.fullname === 'string' ? value.fullname : null;
    const title = typeof value.name === 'string' ? value.name : null;
    const description = typeof value.description === 'string' ? value.description : null;
    const references = Array.isArray(value.references) ? value.references : [];
    const cves = collectCves(references);
    entries.push({
      module: modulePath,
      title,
      description,
      cves,
      referenceCount: references.length
    });
  }
  entries.sort((a, b) => {
    const titleA = (a.title ?? '').toLowerCase();
    const titleB = (b.title ?? '').toLowerCase();
    if (titleA < titleB) return -1;
    if (titleA > titleB) return 1;
    return 0;
  });
  return entries;
};

const loadJsonFile = async path => {
  const content = await readFile(path, 'utf8');
  return JSON.parse(content);
};

const collectVendorProductMap = async () => {
  const map = new Map();

  try {
    const kev = await loadJsonFile(kevPath);
    const vulnerabilities = Array.isArray(kev?.vulnerabilities) ? kev.vulnerabilities : [];
    for (const entry of vulnerabilities) {
      const cve = typeof entry?.cveID === 'string' ? entry.cveID.trim() : '';
      const vendor = typeof entry?.vendorProject === 'string' ? entry.vendorProject.trim() : '';
      const product = typeof entry?.product === 'string' ? entry.product.trim() : '';
      if (!cve || (!vendor && !product)) {
        continue;
      }
      map.set(cve, { vendor, product, source: 'kev' });
    }
  } catch (error) {
    throw new Error(`Failed to load ${kevPath}: ${error.message}`);
  }

  try {
    const historic = await loadJsonFile(historicPath);
    if (Array.isArray(historic)) {
      for (const entry of historic) {
        const cve = typeof entry?.cve === 'string' ? entry.cve.trim() : '';
        const vendor = typeof entry?.vendor === 'string' ? entry.vendor.trim() : '';
        const product = typeof entry?.product === 'string' ? entry.product.trim() : '';
        if (!cve || (!vendor && !product) || map.has(cve)) {
          continue;
        }
        map.set(cve, { vendor, product, source: 'historic' });
      }
    }
  } catch (error) {
    throw new Error(`Failed to load ${historicPath}: ${error.message}`);
  }

  return map;
};

const buildVendorProductCatalog = (metasploitEntries, cveMap) => {
  const catalog = new Map();

  for (const entry of metasploitEntries) {
    const cves = Array.isArray(entry?.cves) ? entry.cves : [];
    for (const cve of cves) {
      const info = cveMap.get(cve);
      if (!info) {
        continue;
      }
      const vendor = info.vendor.trim();
      const product = info.product.trim();
      if (!vendor && !product) {
        continue;
      }
      const key = `${vendor.toLowerCase()}||${product.toLowerCase()}`;
      let record = catalog.get(key);
      if (!record) {
        record = { vendor, product, cves: new Set(), sources: new Set() };
        catalog.set(key, record);
      }
      record.cves.add(cve);
      record.sources.add(info.source);
    }
  }

  const records = [];
  for (const { vendor, product, cves, sources } of catalog.values()) {
    records.push({
      vendor,
      product,
      cves: Array.from(cves).sort(),
      sources: Array.from(sources).sort()
    });
  }

  records.sort((a, b) => {
    const vendorCompare = a.vendor.localeCompare(b.vendor);
    if (vendorCompare !== 0) {
      return vendorCompare;
    }
    return a.product.localeCompare(b.product);
  });

  return records;
};

const main = async () => {
  await mkdir(dataDir, { recursive: true });

  let metasploitEntries;
  if (args.has('--refresh') || !existsSync(metasploitTitlesPath)) {
    const metadata = await fetchMetasploitMetadata();
    metasploitEntries = buildMetasploitTitles(metadata);
    await writeFile(metasploitTitlesPath, `${JSON.stringify(metasploitEntries, null, 2)}\n`, 'utf8');
    log(`Wrote ${metasploitEntries.length.toLocaleString()} entries to ${metasploitTitlesPath}`);
  } else {
    metasploitEntries = await loadJsonFile(metasploitTitlesPath);
    log(`Loaded ${metasploitEntries.length.toLocaleString()} entries from cache`);
  }

  const cveMap = await collectVendorProductMap();
  const vendorCatalog = buildVendorProductCatalog(metasploitEntries, cveMap);
  await writeFile(metasploitVendorsPath, `${JSON.stringify(vendorCatalog, null, 2)}\n`, 'utf8');
  log(`Wrote ${vendorCatalog.length.toLocaleString()} vendor/product pairs to ${metasploitVendorsPath}`);

  const unmatched = metasploitEntries
    .map(entry => ({ entry, matched: entry.cves.some(cve => cveMap.has(cve)) }))
    .filter(item => !item.matched).length;
  if (unmatched > 0) {
    log(`${unmatched.toLocaleString()} exploit entries had no vendor/product match and were skipped`);
  }
};

try {
  await main();
} catch (error) {
  console.error(error);
  process.exitCode = 1;
}
