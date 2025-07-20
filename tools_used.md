# 🛠️ Tools Used in OSINT Pipeline

---

## 🔍 theHarvester

**Purpose:**  
Gather emails, hostnames, and subdomains from public sources.

**Key Capabilities:**
- Email and username harvesting  
- Subdomain and hostname discovery  
- DNS name resolution  
- Source tracking (e.g., Bing, Hunter, Yahoo)  
- Output formats: JSON, XML, HTML

**When to Use:**  
Use with domains (e.g., `openai.com`) to find emails and infrastructure.

---

## 🌐 Shodan

**Purpose:**  
Discover exposed services on IP addresses or domains using internet-wide scan data.

**Key Capabilities:**
- Open ports  
- Service banners  
- CVEs (partial)  
- PTR hostnames  
- HTTP responses  
- Geolocation  
- SSL certificate info

**When to Use:**  
Use with IPs or domains to find vulnerable or exposed infrastructure.

---

## 📝 Whois

**Purpose:**  
Query domain registration and ownership information.

**Key Capabilities:**
- Registrant name, email, org  
- Registrar and country  
- Domain creation, expiry, update dates  
- Administrative and technical contacts

**When to Use:**  
Use with domains to get insight into domain owners and history.

---

## ⚡ Dnsx

**Purpose:**  
Validate subdomains and resolve DNS records to IP addresses.

**Key Capabilities:**
- DNS A, AAAA, CNAME lookups  
- Mass DNS resolution  
- Filters wildcard or unrelated domains  
- Outputs clean, resolvable hosts for scanning

**When to Use:**  
Use with subdomain lists (e.g., from Subfinder) to get real, working hosts.

---

## 🛰️ Subfinder

**Purpose:**  
Find subdomains of a domain using passive reconnaissance.

**Key Capabilities:**
- Fast, passive subdomain enumeration  
- Uses many public sources  
- Supports API keys  
- Clean output format (JSON / plain)

**When to Use:**  
Use with domains to get a wide list of subdomains for scanning or resolution.

---
