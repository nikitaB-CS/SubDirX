import json
import threading
from flask import Flask, render_template, request, send_file, jsonify, Response, stream_with_context
from main import run_scan, results, stream_queue

app = Flask(__name__)

# shared scan state
scan_state = {"running": False, "stop": False}


# ─── Main page ────────────────────────────────────────────────────

@app.route("/", methods=["GET", "POST"])
def home():
    scan_results = None

    if request.method == "POST":
        option   = request.form.get("option")
        domain   = request.form.get("domain")
        base_url = request.form.get("base_url")

        scan_state["running"] = True
        scan_state["stop"]    = False

        scan_results = run_scan(option, domain, base_url, scan_state)

        scan_state["running"] = False

    return render_template("index.html", results=scan_results)


# ─── Live scan via SSE ────────────────────────────────────────────

@app.route("/scan", methods=["POST"])
def scan_start():
    option       = request.form.get("option")
    domain       = request.form.get("domain")
    base_url     = request.form.get("base_url")
    custom_words = request.form.get("custom_words")  # newline-separated string or None

    if scan_state["running"]:
        return jsonify({"ok": False, "error": "Scan already running"}), 400

    while not stream_queue.empty():
        try: stream_queue.get_nowait()
        except: break

    results["subdomains"].clear()
    results["directories"].clear()
    results["dns"].clear()

    scan_state["running"] = True
    scan_state["stop"]    = False

    # Parse custom wordlist if provided
    words = None
    if custom_words:
        words = [w.strip() for w in custom_words.split('\n') if w.strip()]

    def bg():
        run_scan(option, domain, base_url, scan_state, custom_wordlist=words)
        scan_state["running"] = False

    threading.Thread(target=bg, daemon=True).start()
    return jsonify({"ok": True})


@app.route("/stream")
def stream():
    """SSE endpoint — pushes events from stream_queue to the browser."""
    def generate():
        yield "retry: 1000\n\n"
        while True:
            try:
                event = stream_queue.get(timeout=30)
                etype = event["type"]
                edata = json.dumps(event["data"])
                yield f"event: {etype}\ndata: {edata}\n\n"
                if etype == "done":
                    break
            except Exception:
                # heartbeat to keep connection alive
                yield ": heartbeat\n\n"

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no"
        }
    )


# ─── Stop / Reset ────────────────────────────────────────────────

@app.route("/stop", methods=["POST"])
def stop():
    scan_state["stop"] = True
    return jsonify({"ok": True})


@app.route("/reset", methods=["POST"])
def reset():
    scan_state["stop"]    = True
    scan_state["running"] = False
    results["subdomains"].clear()
    results["directories"].clear()
    results["dns"].clear()
    return jsonify({"ok": True})


# ─── Downloads ───────────────────────────────────────────────────

@app.route("/download/<dtype>")
def download(dtype):
    if dtype == "html":
        return send_file("report.html", as_attachment=True)
    elif dtype == "txt":
        return send_file("report.txt", as_attachment=True)
    elif dtype == "json":
        return send_file("report.json", as_attachment=True)


if __name__ == "__main__":
    app.run(debug=True, threaded=True)