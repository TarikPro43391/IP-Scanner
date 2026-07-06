#!/usr/bin/env python3
"""
IP Scanner - Flask Web App
Sadece eğitim/test amaçlı. Yalnızca sahibi olduğun veya izinli
sistemlerde kullan.
"""

import socket
import threading
import queue
import uuid
import time
from datetime import datetime

from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCBind", 135: "MSRPC",
    139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt",
    25565: "Minecraft", 27017: "MongoDB"
}

# Aktif taramaları bellekte tut: {scan_id: {...}}
SCANS = {}
SCANS_LOCK = threading.Lock()

MAX_PORTS_PER_SCAN = 5000  # kötüye kullanım / aşırı yük koruması


def grab_banner(sock):
    try:
        sock.settimeout(1)
        banner = sock.recv(1024).decode(errors="ignore").strip()
        return banner[:120] if banner else ""
    except Exception:
        return ""


def scan_worker(scan_id, target_ip, timeout, port_queue):
    while True:
        try:
            port = port_queue.get_nowait()
        except queue.Empty:
            return
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                service = COMMON_PORTS.get(port, "Bilinmiyor")
                banner = grab_banner(sock)
                with SCANS_LOCK:
                    SCANS[scan_id]["open_ports"].append({
                        "port": port,
                        "service": service,
                        "banner": banner
                    })
            sock.close()
        except Exception:
            pass
        finally:
            with SCANS_LOCK:
                SCANS[scan_id]["scanned"] += 1
            port_queue.task_done()


def run_scan(scan_id, target_ip, ports, threads, timeout):
    port_queue = queue.Queue()
    for p in ports:
        port_queue.put(p)

    worker_threads = []
    for _ in range(min(threads, len(ports))):
        t = threading.Thread(target=scan_worker, args=(scan_id, target_ip, timeout, port_queue))
        t.daemon = True
        t.start()
        worker_threads.append(t)

    for t in worker_threads:
        t.join()

    with SCANS_LOCK:
        SCANS[scan_id]["status"] = "done"
        SCANS[scan_id]["finished_at"] = datetime.now().strftime("%H:%M:%S")
        SCANS[scan_id]["open_ports"].sort(key=lambda x: x["port"])


def parse_ports(port_str):
    ports = set()
    for part in port_str.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start, end = part.split("-")
            start, end = int(start), int(end)
            for p in range(start, end + 1):
                ports.add(p)
        else:
            ports.add(int(part))
    return sorted(ports)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/resolve", methods=["POST"])
def resolve():
    data = request.get_json()
    target = data.get("target", "").strip()
    if not target:
        return jsonify({"error": "Hedef boş olamaz"}), 400
    try:
        ip = socket.gethostbyname(target)
        try:
            reverse_host = socket.gethostbyaddr(ip)[0]
        except Exception:
            reverse_host = None
        return jsonify({
            "target": target,
            "ip": ip,
            "reverse_dns": reverse_host
        })
    except socket.gaierror:
        return jsonify({"error": f"'{target}' çözülemedi"}), 400


@app.route("/api/scan", methods=["POST"])
def start_scan():
    data = request.get_json()
    target = data.get("target", "").strip()
    port_str = data.get("ports", "1-1024").strip()
    threads = int(data.get("threads", 200))
    timeout = float(data.get("timeout", 0.7))

    if not target:
        return jsonify({"error": "Hedef boş olamaz"}), 400

    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        return jsonify({"error": f"'{target}' çözülemedi"}), 400

    try:
        ports = parse_ports(port_str)
    except Exception:
        return jsonify({"error": "Port formatı geçersiz. Örn: 1-1024 veya 80,443,22"}), 400

    if not ports:
        return jsonify({"error": "Geçerli port bulunamadı"}), 400

    if len(ports) > MAX_PORTS_PER_SCAN:
        return jsonify({"error": f"Tek seferde en fazla {MAX_PORTS_PER_SCAN} port taranabilir"}), 400

    threads = max(1, min(threads, 500))
    timeout = max(0.2, min(timeout, 5.0))

    scan_id = str(uuid.uuid4())
    with SCANS_LOCK:
        SCANS[scan_id] = {
            "target": target,
            "ip": ip,
            "total_ports": len(ports),
            "scanned": 0,
            "open_ports": [],
            "status": "running",
            "started_at": datetime.now().strftime("%H:%M:%S"),
            "finished_at": None
        }

    t = threading.Thread(target=run_scan, args=(scan_id, ip, ports, threads, timeout))
    t.daemon = True
    t.start()

    return jsonify({"scan_id": scan_id})


@app.route("/api/scan/<scan_id>", methods=["GET"])
def scan_status(scan_id):
    with SCANS_LOCK:
        scan = SCANS.get(scan_id)
        if not scan:
            return jsonify({"error": "Tarama bulunamadı"}), 404
        # kopya döndür
        return jsonify(dict(scan))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
