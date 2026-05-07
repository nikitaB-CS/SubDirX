
# SubDirX — Web Reconnaissance Suite

A full-stack, real-time web reconnaissance tool for subdomain enumeration, directory brute-forcing, and DNS intelligence gathering — built with Python, Flask, and AsyncIO.


## Features

- Subdomain Enumeration** — Scans for live subdomains with DNS validation before requesting
-Directory Brute-Forcing** — Discovers hidden paths with soft-404 detection to minimize false positives
- DNS Intelligence** — Retrieves A, MX, NS, TXT, and CNAME records for any domain
- Live Results via SSE** — Results stream to the browser dashboard in real time using Server-Sent Events
- Custom Wordlist Upload** — Upload your own .txt wordlist for targeted scans
- Multi-format Reports** — Export scan results as HTML, JSON, or TXT
- Stop / Reset Controls** — Cancel a running scan at any time from the UI

---

## Tech Stack

| Layer  | Technology |
| Backend : Python, Flask, AsyncIO, AioHTTP 
| Frontend : HTML, CSS, Vanilla JavaScript, SSE 
| DNS :  Python socket, nslookup, subprocess 
| Reporting : JSON, HTML template engine, plain text 



## Project Structure


SubDirX/
├── main.py               # Core scan engine (subdomain, directory, DNS)
├── app.py                # Flask server & SSE streaming endpoints
├── reporttemplate.html   # HTML report template
├── requirements.txt      # Python dependencies
└── templates/
    └── index.html        # Frontend dashboard UI



## Installation & Usage

1. Clone the repository
git clone https://github.com/nikitaB-CS/SubDirX.git
cd SubDirX

2. Install dependencies
pip install -r requirements.txt

3. Run the app
python app.py

4. Open in browser
http://localhost:5000


---

## How It Works

1. Enter a **domain** and **base URL** in the dashboard
2. Select a scan type — Subdomain, Directory, or Both
3. Optionally upload a custom wordlist
4. Click **Run Scan** — results appear live on the dashboard
5. Download the report in your preferred format

---

## Screenshots

> _Add screenshots of the dashboard here_

---

## Scan Modes

| Mode | Description |

| Subdomain Scan : Enumerates subdomains using DNS resolution + HTTP probing 
| Directory Scan : Brute-forces paths with baseline comparison for accuracy 
| Run Both : Full recon — subdomains first, then directories on each 
| DNS Lookup : Fetches all DNS record types for the target domain 

---

## Tools & Concepts Used

- Async HTTP requests with AsyncIO + AioHTTP
- Server-Sent Events (SSE) for real-time browser updates
- Soft-404 detection via response length baseline comparison
- DNS resolution using Python socket and nslookup
- Multi-threaded Flask server with background scan threads

---

## Author

**Nikita Birhade**  
Cybersecurity & Forensics Student




## Disclaimer

> This tool is intended for **educational purposes and authorized security testing only**.  
> Do not use SubDirX against systems you do not own or have explicit permission to test.  
> The author is not responsible for any misuse.

