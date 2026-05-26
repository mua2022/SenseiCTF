/**
 * I heard the song from my master leaking of secrets
 * Deep down all i wanted was to be like him
 * Yes as him Sensei
 * Deep in the codes all night
 * Hacking and cracking stuff
 * But why cant i find the secrets
 */

'use strict';
const express = require('express');
const fs      = require('fs');
const path    = require('path');

const app  = express();
const PORT = process.env.PORT || 3002;

const APP_ROOT = __dirname;

/* ── Simulated RSC component registry ──────────────────────────────────── */
const COMPONENTS = {
  Dashboard: { title: 'Dashboard', stats: { users: 1284, revenue: '$48,920', uptime: '99.9%' } },
  Settings:  { title: 'Settings',  fields: ['name', 'email', 'plan'] },
  Billing:   { title: 'Billing',   plan: 'Pro', nextBillingDate: '2026-06-01' },
};

function processRSCPayload(body) {
  const lines  = body.split('\n').filter(l => l.trim());
  const output = [];

  for (const line of lines) {
    // $S rows: sourcemap file inclusion
    if (line.startsWith('$S')) {
     
      const rawPath   = line.slice(2).trim();                     
      const resolved  = path.resolve(APP_ROOT, rawPath);            

      
      const isJs = resolved.endsWith('.js') || resolved.endsWith('.ts') || resolved.endsWith('.jsx');
      if (!isJs) {
        
        output.push({ type: 'sourcemap', error: `${rawPath}: not a recognised source extension` });
        continue;
      }

      try {
        const src = fs.readFileSync(resolved, 'utf8');               
        output.push({
          type:    'sourcemap',
          file:    rawPath,
          content: src,                                               
        });
      } catch (e) {
        output.push({ type: 'sourcemap', error: e.message });
      }

    } else if (line.startsWith('J')) {
      try   { output.push({ type: 'data',      data: JSON.parse(line.slice(1)) }); }
      catch { output.push({ type: 'data',      error: 'invalid JSON' }); }

    } else if (line.startsWith('P')) {
      const name = line.slice(1).trim();
      const comp = COMPONENTS[name];
      output.push(comp
        ? { type: 'component', name, props: comp }
        : { type: 'component', error: `unknown component: ${name}` });

    } else {
      output.push({ type: 'unknown', raw: line });
    }
  }

  return output;
}

/* ── Middleware ─────────────────────────────────────────────────────────── */
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.text({ type: ['text/x-component', 'text/plain', 'application/octet-stream'] }));
app.use(express.json());

/* ── Routes ─────────────────────────────────────────────────────────────── */
app.get('/robots.txt', (_, res) => {
  res.type('text/plain').send(
    'User-agent: *\nDisallow: /admin\nDisallow: /config\nDisallow: /api/rsc\n# Internal RSC endpoint: /api/rsc'
  );
});

app.get('/_next/static/chunks/app-manifest.json', (_, res) => {
  res.json({
    version: '14.0.3',
    rscEndpoint: '/api/rsc',
    rscContentType: 'text/x-component',
    sourceRoot: APP_ROOT,
    sourcemapTag: '$S',
    note: 'source maps enabled for debugging',
  });
});

app.get('/api/components', (_, res) => res.json(Object.keys(COMPONENTS)));

/* ─── THE VULNERABLE ENDPOINT ─────────────────────────────────────────── */
app.post('/api/rsc', (req, res) => {
  const body = typeof req.body === 'string' ? req.body : JSON.stringify(req.body);
  if (!body?.trim()) return res.status(400).json({ error: 'empty RSC payload' });

  const result = processRSCPayload(body);
  res.setHeader('Content-Type', 'text/x-component');
  res.json({ rsc: result });
});

app.listen(PORT, () => {
  console.log(`[CVE-2025-55183] SenseiCloud running on http://localhost:${PORT}`);
  console.log(`  Secrets at    : config/secrets.js`);
  console.log(`  Vulnerable endpoint: POST /api/rsc (Content-Type: text/x-component)`);
});
