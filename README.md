# Comprehensive Pentesting and Bug Hunting Methodology

This guide outlines a comprehensive methodology for conducting penetration testing (pentesting) and bug hunting on web applications, networks, and systems. This methodology covers everything from initial reconnaissance to vulnerability discovery and exploitation.

## 1. Reconnaissance (Recon)

### 1.1. Passive Reconnaissance
- **1.1.1. WHOIS Lookup:** Gather information about the domain registration details.
- **1.1.2. DNS Enumeration:** Enumerate DNS records using tools like `dnsenum`, `fierce`, or `dig`.
- **1.1.3. Subdomain Enumeration:**
  - Use tools like `Sublist3r`, `Amass`, `Assetfinder`, `crt.sh`, and `dnsdumpster`.
- **1.1.4. Google Dorking:** Use advanced Google search queries to find sensitive information exposed online.
- **1.1.5. Social Media Profiling:** Analyze the target's social media presence (LinkedIn, Twitter, etc.) for insights.
- **1.1.6. Shodan and Censys Search:** Identify exposed services and devices related to the target.
- **1.1.7. Wayback Machine:** Look for older versions of the target’s website to uncover deprecated or unpatched content.

### 1.2. Active Reconnaissance
- **1.2.1. Port Scanning:** Use `nmap`, `masscan`, or `Unicornscan` to identify open ports and services.
- **1.2.2. Banner Grabbing:** Identify service versions using `nmap`, `Netcat`, or `Telnet`.
- **1.2.3. Service Enumeration:**
  - **Web:** `Nikto`, `Dirb`, `Gobuster`, `ffuf` for directory brute-forcing.
  - **SMTP:** Use `smtp-user-enum`.
  - **SNMP:** Use `snmpwalk` or `onesixtyone`.
- **1.2.4. Vulnerability Scanning:** Run automated scanners like `Nessus`, `OpenVAS`, or `Qualys`.

## 2. Information Gathering
- **2.1. Fingerprinting Web Application Technologies**
  - Use `Wappalyzer`, `BuiltWith`, or `whatweb` to identify technologies (e.g., CMS, frameworks, libraries).
- **2.2. Identify Endpoints and Parameters**
  - Use `Burp Suite`, `OWASP ZAP`, or `ParamMiner` to find hidden parameters.
- **2.3. SSL/TLS Analysis**
  - Use `sslscan` or `testssl.sh` to identify weaknesses in SSL/TLS configurations.
- **2.4. Identifying Files and Directories**
  - Use tools like `Dirb`, `Dirbuster`, `Gobuster`, or `ffuf` to enumerate hidden files and directories.
- **2.5. Identifying API Endpoints**
  - Use `Postman`, `Insomnia`, or `Burp Suite` to test API endpoints for functionality and vulnerabilities.
- **2.6. Analyze JavaScript Files**
  - Look for sensitive information or hidden endpoints in JavaScript files.
- **2.7. Check for Backup Files**
  - Search for publicly accessible backup files (`.bak`, `.old`, `.zip`).
- **2.8. Search for Misconfigurations**
  - Identify potential misconfigurations using `nmap`, manual inspection, and automated tools.

## 3. Vulnerability Discovery

### 3.1. Injection Attacks
- **3.1.1. SQL Injection (SQLi):** Test for SQLi using manual techniques, `sqlmap`, and Burp Suite.
- **3.1.2. Command Injection:** Attempt to inject OS commands using input fields.
- **3.1.3. NoSQL Injection:** Test for NoSQL vulnerabilities in applications using NoSQL databases.
- **3.1.4. LDAP Injection:** Test LDAP queries for injection vulnerabilities.
- **3.1.5. XML External Entity (XXE):** Test XML parsers for XXE vulnerabilities.
- **3.1.6. Server-Side Template Injection (SSTI):** Inject payloads into templates to execute arbitrary code.
- **3.1.7. CRLF Injection:** Inject carriage return and line feed characters to manipulate HTTP headers.

### 3.2. Cross-Site Scripting (XSS)
- **3.2.1. Reflected XSS:** Inject malicious scripts into URL parameters or forms.
- **3.2.2. Stored XSS:** Look for persistent XSS vulnerabilities where the payload is stored on the server.
- **3.2.3. DOM-Based XSS:** Analyze JavaScript code to identify DOM-based XSS vulnerabilities.
- **3.2.4. Blind XSS:** Use tools like `XSS Hunter` to detect XSS vulnerabilities that do not immediately return a response.

### 3.3. Cross-Site Request Forgery (CSRF)
- **3.3.1. Test for CSRF Tokens:** Look for missing or weak CSRF tokens in requests.
- **3.3.2. CSRF in JSON Requests:** Test JSON endpoints for CSRF vulnerabilities.

### 3.4. Authentication and Session Management
- **3.4.1. Brute-Force Login:** Use tools like `Hydra`, `Burp Suite`, or `WFuzz` to brute-force login forms.
- **3.4.2. Test Session Cookies:** Check for issues like insecure cookies, weak session IDs, or lack of secure flags.
- **3.4.3. Multi-Factor Authentication (MFA) Bypass:** Look for ways to bypass MFA using tools like `Burp Suite`.
- **3.4.4. JWT Attacks:** Test JSON Web Tokens for weak secrets, algorithm manipulation, and token tampering.

### 3.5. Access Control Flaws
- **3.5.1. Horizontal Privilege Escalation:** Attempt to access resources or perform actions as another user.
- **3.5.2. Vertical Privilege Escalation:** Attempt to escalate privileges to gain higher-level access.
- **3.5.3. IDOR (Insecure Direct Object References):** Test for IDOR by manipulating object references in the URL or request body.

### 3.6. File Upload Vulnerabilities
- **3.6.1. Upload Restrictions Bypass:** Attempt to upload dangerous files by bypassing content-type or extension restrictions.
- **3.6.2. File Inclusion (LFI/RFI):** Test for Local File Inclusion (LFI) and Remote File Inclusion (RFI) vulnerabilities.
- **3.6.3. ImageTragick:** Test for vulnerabilities related to image file processing (e.g., ImageMagick exploit).

### 3.7. Information Disclosure
- **3.7.1. Error Messages:** Check if detailed error messages expose sensitive information.
- **3.7.2. Exposed Git Repositories:** Look for exposed `.git` directories or other VCS remnants.
- **3.7.3. Sensitive Data Exposure:** Identify exposed sensitive information in responses, source code, or configurations.
- **3.7.4. Predictable Resource Location:** Check for predictable URLs or filenames that may expose sensitive information.

### 3.8. Security Misconfigurations
- **3.8.1. Insecure HTTP Headers:** Analyze security-related HTTP headers like `Content-Security-Policy`, `X-Frame-Options`, etc.
- **3.8.2. Directory Listing:** Check if directory listing is enabled on the server.
- **3.8.3. Debug Mode:** Identify if debug mode is enabled in production environments.
- **3.8.4. Outdated Software:** Identify outdated software versions that might be vulnerable.

### 3.9. Business Logic Flaws
- **3.9.1. Identify Flaws in Business Processes:** Analyze workflows for bypasses or flaws in logic that can be exploited.
- **3.9.2. Race Conditions:** Test for race conditions by making concurrent requests.

## 4. Exploitation

### 4.1. Exploiting Discovered Vulnerabilities
- **4.1.1. Develop Exploits:** Write custom exploits to demonstrate the impact of discovered vulnerabilities.
- **4.1.2. Automated Exploitation:** Use tools like `Metasploit` or `sqlmap` for automated exploitation.
- **4.1.3. Privilege Escalation:** Attempt to escalate privileges after initial exploitation.

### 4.2. Reporting
- **4.2.1. Document Findings:** Write detailed reports including proof of concepts, screenshots, and remediation suggestions.
- **4.2.2. Impact Analysis:** Describe the potential impact of each vulnerability.
- **4.2.3. Remediation Advice:** Provide clear, actionable advice on how to fix the discovered issues.

## 5. Continuous Monitoring and Retesting

### 5.1. Regular Scanning
- Set up regular scans to detect new vulnerabilities or misconfigurations.
  
### 5.2. Bug Bounty Platforms
- Submit valid bugs to platforms like HackerOne, Bugcrowd, or private programs.
  
### 5.3. Patch Verification
- Verify that patches or fixes have been properly implemented.

## 6. Legal and Ethical Considerations
- **6.1. Scope Definition:** Ensure the scope of the pentest or bug hunt is clearly defined and legally agreed upon.
- **6.2. Responsible Disclosure:** Follow responsible disclosure policies when reporting vulnerabilities.
- **6.3. Compliance:** Ensure that testing adheres to relevant laws and regulations (e.g., GDPR, HIPAA).
- **6.4. Obtain Permissions:** Always obtain proper permissions before testing.

## 7. Tools and Resources

### 7.1. Web Application Testing Tools:
- **Burp Suite**, **OWASP ZAP**, **Postman**

### 7.2. Network Scanning Tools:
- **Nmap**, **Masscan**, **Wireshark**

### 7.3. Exploitation Frameworks:
- **Metasploit**, **sqlmap**, **BeEF**

### 7.4. Wordlists and Fuzzing:
- **SecLists**, **Rockyou**, **wfuzz** **I'll add some lists to the repo aswell**

### 7.5. Cloud Security Tools:
- **ScoutSuite**, **Pacu**, **CloudSploit**

### 7.6. Mobile Application Testing:
- **MobSF**, **Frida**, **Drozer**

### 7.7. Open Source Intelligence (OSINT):
- **theHarvester**, **Maltego**, **Recon-ng**

- **there's a bunch of tools you can use. I'm making some but you can always look tools up or ask me for tools on certain vulns etc.**
