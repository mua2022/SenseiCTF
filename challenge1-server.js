/**
 * NextMart — E-Commerce Platform
 * CTF Challenge: CVE-2025-55182 (React2Shell)
 *
 * Vulnerability: The /_next/flight endpoint processes React Server Component
 * "Flight" protocol payloads using an insecure deserializer.
 *
 * The Flight wire format:
 *   <rowId>:<tag><value>\n
 *
 * Tags:
 *   I  — Import: requires a Node.js module  (e.g.  0:I["child_process","execSync"])
 *   C  — Call:   invokes a method on a loaded module
 *              (e.g.  1:C[0,"execSync",["id"]])
 *
 * The real CVE uses react-server-dom-webpack's decodeReply() which processes
 * these tags without validation, allowing an attacker to load arbitrary modules
 * and call arbitrary methods — including child_process.execSync() → RCE.
 */

'use strict';
const express = require('express');
const fs      = require('fs');
const path    = require('path');

const app  = express();
const PORT = process.env.PORT || 3001;

/* ── Flag (hidden from direct web access) ──────────────────────────────── */
const FLAG_PATH = path.join(__dirname, '.flag');
fs.writeFileSync(FLAG_PATH, 'sensei{FL1GHT_D3S3R14L_RC3_CVE_2025_55182}\n', { mode: 0o600 });

/* ── In-memory module registry for the Flight deserializer ─────────────── */
const moduleRegistry = {};

/**
 * Simulates react-server-dom-webpack's insecure Flight deserializer.
 * Processes rows in the React Flight wire format without input validation.
 */
function flightDeserialize(body) {
  const output = [];
  const lines  = body.split('\n').filter(l => l.trim());

  for (const line of lines) {
    // Row format:  <id>:<tag><json_value>
    const m = line.match(/^([0-9a-f]+):([A-Za-z$])(.+)$/);
    if (!m) { output.push({ row: line, error: 'malformed row' }); continue; }

    const [, rowId, tag, raw] = m;

    try {
      if (tag === 'I') {
        // ──────────────────────────────────────────────────────────────────
        // VULNERABLE: Import row — loads an arbitrary Node.js module.
        // Real CVE: react-server-dom processes "$I" entries in the RSC
        // payload and calls require() with attacker-supplied module path.
        // ──────────────────────────────────────────────────────────────────
        const [modulePath, exportName] = JSON.parse(raw);
        const mod = require(modulePath);                  // ← SINK (no validation)
        moduleRegistry[rowId] = mod;
        output.push({ row: rowId, tag: 'I', loaded: modulePath });

      } else if (tag === 'C') {
        // ──────────────────────────────────────────────────────────────────
        // VULNERABLE: Call row — invokes a method on a previously loaded
        // module.  Combined with 'I', this gives full RCE.
        // ──────────────────────────────────────────────────────────────────
        const [refId, method, args] = JSON.parse(raw);
        const mod = moduleRegistry[String(refId)];
        if (!mod) { output.push({ row: rowId, error: `module ${refId} not loaded` }); continue; }
        const result = mod[method](...(Array.isArray(args) ? args : [args])); // ← SINK
        output.push({ row: rowId, tag: 'C', result: result?.toString() });

      } else if (tag === 'J') {
        // Normal JSON data row (safe)
        output.push({ row: rowId, tag: 'J', data: JSON.parse(raw) });

      } else {
        output.push({ row: rowId, tag, raw });
      }
    } catch (err) {
      output.push({ row: rowId, error: err.message });
    }
  }
  return output;
}

/* ── Middleware ─────────────────────────────────────────────────────────── */
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());
app.use(express.text({ type: ['text/x-component', 'application/octet-stream', 'text/plain'] }));

/* ── Routes ─────────────────────────────────────────────────────────────── */
app.get('/robots.txt', (_, res) => {
  res.type('text/plain').send(
    'User-agent: *\nDisallow: /admin\nDisallow: /_next/flight\nDisallow: /.env'
  );
});

app.get('/_next/buildManifest.json', (_, res) => {
  res.json({
    pages: {
      '/':        ['static/chunks/main.js'],
      '/products':['static/chunks/products.js'],
    },
    rscEndpoint: '/_next/flight',
    rscContentType: 'text/x-component',
    version: '13.4.1',
  });
});

/* ─── THE VULNERABLE ENDPOINT ─────────────────────────────────────────── */
app.post('/_next/flight', (req, res) => {
  const body = typeof req.body === 'string' ? req.body : JSON.stringify(req.body);
  if (!body || !body.trim()) {
    return res.status(400).json({ error: 'empty Flight payload' });
  }
  const result = flightDeserialize(body);
  res.setHeader('Content-Type', 'text/x-component');
  res.json({ rows: result });
});

/* Normal pages */
app.get('/api/products', (_, res) => {
  res.json([
    { id: 1, name: 'Wireless Headphones', price: 79.99 },
    { id: 2, name: 'USB-C Hub',           price: 34.99 },
    { id: 3, name: 'Mechanical Keyboard', price: 129.99 },
  ]);
});

app.listen(PORT, () => {
  console.log(`[CVE-2025-55182] NextMart running on http://localhost:${PORT}`);
  console.log(`  Flag stored at: ${FLAG_PATH}`);
  console.log(`  Vulnerable endpoint: POST /_next/flight (Content-Type: text/x-component)`);
});
