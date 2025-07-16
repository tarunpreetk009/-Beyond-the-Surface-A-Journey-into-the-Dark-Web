# -Beyond-the-Surface-A-Journey-into-the-Dark-Web
This project was focused on enhancing dark web intelligence gathering by integrating multiple hidden search engines, validating .onion links in real-time, and providing a secure platform tailored for analysts and ethical researchers. 

# Beyond the Surface: A Journey into the Dark Web

A dark web OSINT (Open Source Intelligence) automation tool that enables secure and efficient extraction of actionable intelligence from onion domains.

![Screenshot](https://github.com/yourusername/yourrepo/blob/main/path/to/screenshot.png)

---

## Project Overview

**Beyond the Surface** is an OSINT platform designed to scan and analyze .onion websites using multiple verified dark web search engines. It automates data collection while maintaining anonymity via TOR, and presents results in a clean, interactive web interface for analysts, researchers, and law enforcement applications.


## Key Features

- **Keyword-based Search** — Query across 1,000+ onion links with custom keyword filters.
- **Multi-engine Integration** — Fetches results from multiple verified sources.
- **Anonymous Access via TOR** — Routes all requests through the TOR network.
- **Automated Crawling** — Uses `Puppeteer` for fast, headless scraping.
- **Structured Output** — Exports data in JSON and CSV formats.
- **Remediation Tagging System** — Flags sensitive content based on keyword criticality.
- **User Authentication** — Secure login/register system with hashed passwords.
- **Search Metrics Dashboard** — Track success rate, indexed links, and response times.


## Tech Stack

| Frontend        | Backend        | Data Handling      | Others             |
|-----------------|----------------|--------------------|--------------------|
| HTML, CSS (Tailwind) | Flask (Python) | SQLite, CSV, JSON | TOR, Puppeteer, BeautifulSoup |


## UI Snapshots

| Search UI | Results Page | Target Onion Site |
|-----------|--------------|-------------------|
| ![main](./main.png) | ![results](./active-link.png) | ![target](./target-site.png) |

## Security & Anonymity

- All scraping is routed through TOR to preserve anonymity.
- Input validation and bcrypt password hashing are used for authentication.
- Crawlers are sandboxed to reduce the risk of malware execution.

## How to Run

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/darkweb-osint.git
   cd darkweb-osint

