import asyncio
import sys
import socket
import subprocess
import queue
import datetime
from typing import Counter

if sys.platform.startswith("win"):
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

import aiohttp
from rich.console import Console
import tqdm

console = Console()

# shared queue for SSE live streaming
stream_queue = queue.Queue()

results = {
    "subdomains": [],
    "directories": [],
    "dns": {}
}

TIMEOUT = aiohttp.ClientTimeout(total=8)

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
}

# ---------------- WORDLISTS ----------------

SUBDOMAIN_WORDS = [
    "www", "admin", "dev", "test", "api", "staging", "beta", "mail"
]

DIR_WORDS = [
    "admin", "login", "dashboard", "api",
    "uploads", "images", "backup",
    ".git", ".env", "test",
    "dev", "devnote", "dev-notes", "dev_notes",
    "notes", "internal", "debug", "development",
    "simple", "server-status", "files"
]

# ---------------- HELPERS ----------------

def dns_resolves(host):
    try:
        socket.gethostbyname(host)
        return True
    except:
        return False


def push(event_type, data):
    """Push an event into the stream queue for SSE."""
    stream_queue.put({"type": event_type, "data": data})


# ---------------- ASYNC FETCH ----------------

async def fetch(session, url):
    try:
        async with session.get(
            url, headers=HEADERS, allow_redirects=True, ssl=False
        ) as resp:
            body = await resp.read()
            return resp.status, len(body)
    except:
        return None, None


# ---------------- DNS RECORD DUMP ----------------

def dns_lookup(domain):
   
    console.print(f"\n[bold green]🌐 DNS Record Dump — {domain}[/]\n")
    push("status", f"Running DNS lookup for {domain}...")

    dns = {
        "A":     [],
        "MX":    [],
        "NS":    [],
        "TXT":   [],
        "CNAME": []
    }

    # ── A records via socket ──
    try:
        infos = socket.getaddrinfo(domain, None)
        seen = set()
        for info in infos:
            ip = info[4][0]
            if ip not in seen:
                dns["A"].append(ip)
                seen.add(ip)
                console.print(f"[green]A[/green]     {ip}")
                push("dns", {"type": "A", "value": ip})
    except Exception as e:
        console.print(f"[dim]A lookup failed: {e}[/dim]")

    # ── MX / NS / TXT / CNAME via nslookup ──
    record_types = {
        "MX":    "MX",
        "NS":    "NS",
        "TXT":   "TXT",
        "CNAME": "CNAME"
    }

    for rtype, label in record_types.items():
        try:
            cmd = ["nslookup", f"-type={rtype}", domain]
            out = subprocess.check_output(
                cmd, stderr=subprocess.DEVNULL, timeout=5
            ).decode("utf-8", errors="ignore")

            for line in out.splitlines():
                line = line.strip()
                # skip header lines
                if not line or line.startswith("Server") or line.startswith("Address") or line.startswith("Non-authoritative"):
                    continue

                value = None

                if rtype == "MX" and "mail exchanger" in line:
                    parts = line.split("mail exchanger =")
                    if len(parts) > 1:
                        value = parts[1].strip()

                elif rtype == "NS" and "nameserver" in line:
                    parts = line.split("nameserver =")
                    if len(parts) > 1:
                        value = parts[1].strip()

                elif rtype == "TXT" and "text =" in line:
                    parts = line.split("text =")
                    if len(parts) > 1:
                        value = parts[1].strip().strip('"')

                elif rtype == "CNAME" and "canonical name" in line:
                    parts = line.split("canonical name =")
                    if len(parts) > 1:
                        value = parts[1].strip()

                if value and value not in dns[rtype]:
                    dns[rtype].append(value)
                    console.print(f"[green]{label}[/green]{'  ' if len(label)<4 else ' '}   {value}")
                    push("dns", {"type": rtype, "value": value})

        except Exception:
            pass

    results["dns"] = dns
    push("status", "DNS lookup complete.")
    return dns


# ---------------- SUBDOMAIN SCAN ----------------

async def subdomain_scan(domain, _scan_state=None, _wordlist=None):
    words = _wordlist if _wordlist else SUBDOMAIN_WORDS
    console.print(f"\n[bold cyan]🚀 Subdomain Scan[/] ([dim]{len(words)} words[/])\n")
    push("status", f"Starting subdomain scan ({len(words)} words)...")

    async with aiohttp.ClientSession(timeout=TIMEOUT) as session:

        tasks = []

        for sub in words:
            host = f"{sub}.{domain}"
            if not dns_resolves(host):
                continue
            url = f"http://{host}"
            tasks.append((host, asyncio.create_task(fetch(session, url))))

        if not tasks:
            console.print("[yellow]No resolvable subdomains found[/]")
            push("status", "No resolvable subdomains found.")
            return []

        for host, task in tqdm.tqdm(tasks, desc="Scanning", unit="subs"):

            if _scan_state and _scan_state.get("stop"):
                console.print("[yellow]⛔ Scan stopped by user[/]")
                push("status", "Scan stopped by user.")
                break

            status, length = await task

            if status and status < 500:
                if status == 200:
                    console.print(f"[bold green][200][/bold green] {host} → {length} bytes")
                elif status == 403:
                    console.print(f"[bold yellow][403][/bold yellow] {host}")
                elif status in [301, 302]:
                    console.print(f"[bold blue][REDIRECT][/bold blue] {host}")
                else:
                    console.print(f"[dim]{status}[/dim] {host}")

                entry = {"host": host, "status": status, "length": length}
                results["subdomains"].append(entry)
                push("subdomain", entry)

    return results["subdomains"]


# ---------------- DIRECTORY SCAN ----------------

async def dir_scan(base_url, _scan_state=None, _wordlist=None):
    words = _wordlist if _wordlist else DIR_WORDS
    console.print(f"\n[bold yellow]📁 Directory Scan[/] ([dim]{len(words)} words[/])\n")
    push("status", f"Starting directory scan ({len(words)} words)...")

    async with aiohttp.ClientSession(timeout=TIMEOUT) as session:

        baseline_url = f"{base_url}/thispathshouldnotexist123"
        b_status, b_len = await fetch(session, baseline_url)
        use_baseline = True

        if not b_status:
            console.print("[yellow]Baseline blocked → switching to fallback mode[/]\n")
            use_baseline = False
        else:
            console.print(f"[cyan]Baseline → status:{b_status} length:{b_len}[/]\n")

        tasks = []
        for path in words:
            full = f"{base_url}/{path}"
            tasks.append((path, asyncio.create_task(fetch(session, full))))

        for path, task in tqdm.tqdm(tasks, desc="Bruteforcing", unit="paths"):

            if _scan_state and _scan_state.get("stop"):
                console.print("[yellow]⛔ Scan stopped by user[/]")
                push("status", "Scan stopped by user.")
                break

            status, length = await task
            if not status:
                continue

            url = f"{base_url}/{path}"

            if use_baseline:
                if status != b_status or length != b_len:
                    if status == 200:
                        console.print(f"[bold green][200][/bold green] {url} → {length} bytes")
                    elif status == 403:
                        console.print(f"[bold yellow][403][/bold yellow] {url}")
                    elif status in [301, 302]:
                        console.print(f"[bold blue][REDIRECT][/bold blue] {url}")
                    entry = {"url": url, "status": status, "length": length}
                    results["directories"].append(entry)
                    push("directory", entry)
            else:
                if status in [200, 301, 302, 403]:
                    if status == 200:
                        console.print(f"[bold green][200][/bold green] {url}")
                    elif status == 403:
                        console.print(f"[bold yellow][403][/bold yellow] {url}")
                    elif status in [301, 302]:
                        console.print(f"[bold blue][REDIRECT][/bold blue] {url}")
                    entry = {"url": url, "status": status, "length": length}
                    results["directories"].append(entry)
                    push("directory", entry)


# ---------------- TEXT REPORT ----------------

def generate_text_report():
    with open("report.txt", "w") as f:
        f.write("RECON SCAN REPORT\n")
        f.write("=" * 50 + "\n\n")

        f.write("DNS RECORDS:\n")
        for rtype, values in results["dns"].items():
            for v in values:
                f.write(f"- {rtype}: {v}\n")

        f.write("\nSUBDOMAINS FOUND:\n")
        for s in results["subdomains"]:
            f.write(f"- {s['host']} | {s['status']} | {s['length']} bytes\n")

        f.write("\nDIRECTORIES FOUND:\n")
        for d in results["directories"]:
            f.write(f"- {d['url']} | {d['status']} | {d['length']} bytes\n")


# ---------------- HTML REPORT ----------------

def generate_html_report_from_template():
    import os
    template_path = os.path.join(os.path.dirname(__file__), "reporttemplate.html")

    with open(template_path, "r", encoding="utf-8") as f:
        template = f.read()

    sub_rows = ""
    for s in results["subdomains"]:
        status_class = "status200" if s["status"]==200 else \
                       "status403" if s["status"]==403 else \
                       "statusRedirect" if s["status"] in [301,302] else "status404"
        badge = "200" if s["status"]==200 else \
                "403" if s["status"]==403 else \
                "Redirect" if s["status"] in [301,302] else str(s["status"])
        sub_rows += f"<tr class='{status_class}'><td>{s['host']}</td><td><span class='badge'>{badge}</span></td><td>{s['length']}</td></tr>\n"

    dir_rows = ""
    for d in results["directories"]:
        status_class = "status200" if d["status"]==200 else \
                       "status403" if d["status"]==403 else \
                       "statusRedirect" if d["status"] in [301,302] else "status404"
        badge = "200" if d["status"]==200 else \
                "403" if d["status"]==403 else \
                "Redirect" if d["status"] in [301,302] else str(d["status"])
        dir_rows += f"<tr class='{status_class}'><td>{d['url']}</td><td><span class='badge'>{badge}</span></td><td>{d['length']}</td></tr>\n"

    html = template.replace("{{SUBDOMAIN_COUNT}}", str(len(results["subdomains"])))
    html = html.replace("{{DIRECTORY_COUNT}}", str(len(results["directories"])))
    html = html.replace("{{SUBDOMAIN_ROWS}}", sub_rows)
    html = html.replace("{{DIRECTORY_ROWS}}", dir_rows)

    # DNS rows
    dns_rows = ""
    for rtype, values in results["dns"].items():
        for v in values:
            dns_rows += f"<tr><td><span class='dns-badge'>{rtype}</span></td><td>{v}</td></tr>\n"
    if not dns_rows:
        dns_rows = "<tr><td colspan='2' style='color:#aaa;'>No DNS lookup run</td></tr>"

    dns_count = sum(len(v) for v in results["dns"].values())
    html = html.replace("{{DNS_ROWS}}", dns_rows)
    html = html.replace("{{DNS_COUNT}}", str(dns_count))

    output_path = os.path.join(os.path.dirname(__file__), "report.html")
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    console.print("[bold green]✔ HTML report generated: report.html[/]")


# ---------------- JSON REPORT ----------------

def generate_json_report():
    import json
    export = {
        "generated": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "summary": {
            "subdomains":  len(results["subdomains"]),
            "directories": len(results["directories"]),
            "dns_records": sum(len(v) for v in results["dns"].values())
        },
        "dns":         results["dns"],
        "subdomains":  results["subdomains"],
        "directories": results["directories"]
    }
    with open("report.json", "w", encoding="utf-8") as f:
        json.dump(export, f, indent=2)


# ---------------- STATUS GRAPH ----------------

def show_status_graph():
    console.print("\n[bold cyan]STATUS GRAPH[/bold cyan]\n")
    statuses = [d["status"] for d in results["directories"]]
    counter = Counter(statuses)
    for status, count in sorted(counter.items()):
        bar = "█" * count
        if status == 200:
            console.print(f"[green]{status}[/green] {bar} {count}")
        elif status == 403:
            console.print(f"[yellow]{status}[/yellow] {bar} {count}")
        elif status in [301, 302]:
            console.print(f"[blue]{status}[/blue] {bar} {count}")
        else:
            console.print(f"[dim]{status}[/dim] {bar} {count}")


# ---------------- WEB HELPER ----------------

def run_scan(option, domain=None, base_url=None, scan_state=None, custom_wordlist=None):

    async def runner():
        results["subdomains"].clear()
        results["directories"].clear()
        results["dns"].clear()

        if option == "1":
            await subdomain_scan(domain, scan_state, custom_wordlist)

        elif option == "2":
            await dir_scan(base_url, scan_state, custom_wordlist)

        elif option == "3":
            subs = await subdomain_scan(domain, scan_state, custom_wordlist)
            for s in subs:
                if scan_state and scan_state.get("stop"):
                    break
                await dir_scan(f"http://{s['host']}", scan_state, custom_wordlist)
            if not (scan_state and scan_state.get("stop")):
                await dir_scan(base_url, scan_state, custom_wordlist)

        elif option == "4":
            if domain:
                dns_lookup(domain)

    asyncio.run(runner())

    push("done", "Scan complete.")

    generate_text_report()
    generate_html_report_from_template()
    generate_json_report()

    return results


if __name__ == "__main__":
    pass