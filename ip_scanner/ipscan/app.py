#!/usr/bin/env python3
"""
IP Scanner v0.1.1 - Flask Web App
Sadece eğitim/test amaçlı. Yalnızca sahibi olduğun veya izinli
sistemlerde kullan.
"""

import socket
import ssl
import subprocess
import platform
import threading
import queue
import uuid
import time
import csv
import io
import ipaddress
import urllib.request
import urllib.parse
import json as pyjson
from datetime import datetime
from collections import deque
from concurrent.futures import ThreadPoolExecutor

from flask import Flask, render_template, request, jsonify, Response

try:
    import dns.resolver
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

app = Flask(__name__)

VERSION = "0.1.1"

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

# Aktif alt ağ (CIDR) taramaları
SUBNET_SCANS = {}
SUBNET_LOCK = threading.Lock()

# Tarama geçmişi (son N tarama, en yeni en başta)
SCAN_HISTORY = deque(maxlen=25)
HISTORY_LOCK = threading.Lock()

# İptal edilen tarama id'leri
CANCELLED_SCANS = set()
CANCEL_LOCK = threading.Lock()

MAX_PORTS_PER_SCAN = 5000  # kötüye kullanım / aşırı yük koruması
MAX_SUBNET_HOSTS = 256      # en fazla /24
MAX_SUBNET_PORTS = 50       # subnet taramasında host başına port limiti

SSL_PORTS = {443, 8443, 993, 995, 465, 636, 990}

PORT_PRESETS = {
    "web": "80,443,8080,8443,8000,8888",
    "database": "1433,1521,3306,5432,6379,27017,9200",
    "remote": "22,23,3389,5900,5985",
    "mail": "25,110,143,465,587,993,995",
    "gaming": "25565,27015,7777,19132",
    "top100": "1-1024",
}


def grab_banner(sock):
    try:
        sock.settimeout(1)
        banner = sock.recv(1024).decode(errors="ignore").strip()
        return banner[:120] if banner else ""
    except Exception:
        return ""


def grab_ssl_info(target_ip, port, hostname, timeout):
    """443 gibi SSL/TLS portları için sertifika bilgisi çıkar."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.settimeout(timeout + 1)
        with ctx.wrap_socket(raw_sock, server_hostname=hostname or target_ip) as ssock:
            ssock.connect((target_ip, port))
            cert = ssock.getpeercert(binary_form=False)
            if not cert:
                return None
            subject = dict(x[0] for x in cert.get("subject", []))
            issuer = dict(x[0] for x in cert.get("issuer", []))
            return {
                "common_name": subject.get("commonName", "?"),
                "issuer": issuer.get("commonName", "?"),
                "valid_from": cert.get("notBefore", "?"),
                "valid_until": cert.get("notAfter", "?"),
            }
    except Exception:
        return None


def scan_worker(scan_id, target_ip, hostname, timeout, port_queue):
    while True:
        try:
            port = port_queue.get_nowait()
        except queue.Empty:
            return
        with CANCEL_LOCK:
            if scan_id in CANCELLED_SCANS:
                port_queue.task_done()
                continue
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                service = COMMON_PORTS.get(port, "Bilinmiyor")
                banner = grab_banner(sock)
                sock.close()
                ssl_info = None
                if port in SSL_PORTS:
                    ssl_info = grab_ssl_info(target_ip, port, hostname, timeout)
                with SCANS_LOCK:
                    SCANS[scan_id]["open_ports"].append({
                        "port": port,
                        "service": service,
                        "banner": banner,
                        "ssl": ssl_info
                    })
            else:
                sock.close()
        except Exception:
            pass
        finally:
            with SCANS_LOCK:
                SCANS[scan_id]["scanned"] += 1
            port_queue.task_done()


def run_scan(scan_id, target_ip, hostname, ports, threads, timeout):
    port_queue = queue.Queue()
    for p in ports:
        port_queue.put(p)

    worker_threads = []
    for _ in range(min(threads, len(ports))):
        t = threading.Thread(target=scan_worker, args=(scan_id, target_ip, hostname, timeout, port_queue))
        t.daemon = True
        t.start()
        worker_threads.append(t)

    for t in worker_threads:
        t.join()

    with CANCEL_LOCK:
        was_cancelled = scan_id in CANCELLED_SCANS
        CANCELLED_SCANS.discard(scan_id)

    with SCANS_LOCK:
        SCANS[scan_id]["status"] = "cancelled" if was_cancelled else "done"
        SCANS[scan_id]["finished_at"] = datetime.now().strftime("%H:%M:%S")
        SCANS[scan_id]["open_ports"].sort(key=lambda x: x["port"])
        finished_snapshot = dict(SCANS[scan_id])

    with HISTORY_LOCK:
        SCAN_HISTORY.appendleft({
            "scan_id": scan_id,
            "target": finished_snapshot["target"],
            "ip": finished_snapshot["ip"],
            "open_count": len(finished_snapshot["open_ports"]),
            "total_ports": finished_snapshot["total_ports"],
            "status": finished_snapshot["status"],
            "finished_at": finished_snapshot["finished_at"],
        })


def ping_host(target_ip, timeout=1.5):
    """İşletim sistemi ping komutu ile host canlı kontrolü + gecikme (ms)."""
    is_windows = platform.system().lower() == "windows"
    count_flag = "-n" if is_windows else "-c"
    timeout_flag = "-w" if is_windows else "-W"
    timeout_val = str(int(timeout * 1000)) if is_windows else str(int(timeout))

    try:
        start = time.time()
        result = subprocess.run(
            ["ping", count_flag, "1", timeout_flag, timeout_val, target_ip],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout + 2
        )
        elapsed_ms = round((time.time() - start) * 1000, 1)
        alive = result.returncode == 0
        return {"alive": alive, "latency_ms": elapsed_ms if alive else None}
    except Exception:
        return {"alive": False, "latency_ms": None}


def extract_hostname(raw_input):
    """Tam URL, 'domain.com:port', ya da düz domain/IP girişinden hostname çıkarır."""
    raw_input = raw_input.strip()
    if not raw_input:
        return ""

    candidate = raw_input
    if "://" not in candidate:
        candidate = "http://" + candidate

    parsed = urllib.parse.urlparse(candidate)
    hostname = parsed.hostname
    if hostname:
        return hostname

    cleaned = raw_input.split("://")[-1]
    cleaned = cleaned.split("/")[0]
    cleaned = cleaned.split("?")[0]
    cleaned = cleaned.split(":")[0]
    return cleaned.strip()


def query_dns_records(hostname, record_type):
    """Belirtilen tipte DNS kaydını sorgular, dnspython yoksa boş liste döner."""
    if not HAS_DNSPYTHON:
        return []
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 4
        answers = resolver.resolve(hostname, record_type)
        return [rdata.to_text() for rdata in answers]
    except Exception:
        return []


def advanced_resolve(hostname):
    """URL/domain için kapsamlı DNS çözümleme: A, AAAA, CNAME, MX, TXT, NS + reverse DNS."""
    result = {
        "hostname": hostname,
        "a_records": [],
        "aaaa_records": [],
        "cname_chain": [],
        "mx_records": [],
        "ns_records": [],
        "txt_records": [],
        "reverse_dns": {},
        "primary_ip": None,
        "error": None,
    }

    if HAS_DNSPYTHON:
        try:
            current = hostname
            seen = set()
            while current not in seen:
                seen.add(current)
                answers = query_dns_records(current, "CNAME")
                if answers:
                    target = answers[0].rstrip(".")
                    result["cname_chain"].append({"from": current, "to": target})
                    current = target
                else:
                    break
        except Exception:
            pass

        result["a_records"] = [ip.rstrip(".") for ip in query_dns_records(hostname, "A")]
        result["aaaa_records"] = [ip.rstrip(".") for ip in query_dns_records(hostname, "AAAA")]
        result["mx_records"] = query_dns_records(hostname, "MX")
        result["ns_records"] = [r.rstrip(".") for r in query_dns_records(hostname, "NS")]
        result["txt_records"] = query_dns_records(hostname, "TXT")

    if not result["a_records"]:
        try:
            infos = socket.getaddrinfo(hostname, None, socket.AF_INET)
            ips = sorted(set(i[4][0] for i in infos))
            result["a_records"] = ips
        except Exception:
            if not result["cname_chain"]:
                result["error"] = f"'{hostname}' çözülemedi"
                return result

    if result["a_records"]:
        result["primary_ip"] = result["a_records"][0]

    for ip in (result["a_records"] + result["aaaa_records"])[:10]:
        try:
            result["reverse_dns"][ip] = socket.gethostbyaddr(ip)[0]
        except Exception:
            result["reverse_dns"][ip] = None

    return result


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


def _whois_query(server, query, port=43, timeout=5):
    with socket.create_connection((server, port), timeout=timeout) as s:
        s.sendall((query + "\r\n").encode())
        response = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            response += chunk
    return response.decode(errors="ignore")


def whois_lookup(query):
    """IANA üzerinden başlayıp ilgili registry'e yönlendirilen basit WHOIS istemcisi."""
    try:
        response = _whois_query("whois.iana.org", query)
        referral = None
        for line in response.splitlines():
            if line.lower().startswith("refer:"):
                referral = line.split(":", 1)[1].strip()
                break
        if referral:
            response = _whois_query(referral, query)
        return response
    except Exception:
        return None


def traceroute_host(target_ip, max_hops=20, timeout=1.5):
    is_windows = platform.system().lower() == "windows"
    if is_windows:
        cmd = ["tracert", "-h", str(max_hops), "-w", str(int(timeout * 1000)), target_ip]
    else:
        cmd = ["traceroute", "-m", str(max_hops), "-w", str(int(timeout)), target_ip]
    try:
        result = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=max_hops * timeout + 15
        )
        return result.stdout.decode(errors="ignore")
    except Exception:
        return None


def geoip_lookup(ip):
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,isp,org,as,query"
        with urllib.request.urlopen(url, timeout=5) as resp:
            data = pyjson.loads(resp.read().decode())
            if data.get("status") != "success":
                return None
            return data
    except Exception:
        return None


def probe_host_ports(ip_str, ports, timeout):
    open_ports = []
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            if sock.connect_ex((ip_str, port)) == 0:
                open_ports.append({"port": port, "service": COMMON_PORTS.get(port, "Bilinmiyor")})
            sock.close()
        except Exception:
            pass
    return open_ports


def run_subnet_scan(scan_id, network, ports, timeout, max_workers=64):
    hosts = list(network.hosts())
    if not hosts:
        hosts = [network.network_address]

    with SUBNET_LOCK:
        SUBNET_SCANS[scan_id]["total_hosts"] = len(hosts)

    def probe(ip):
        with CANCEL_LOCK:
            if scan_id in CANCELLED_SCANS:
                return
        ip_str = str(ip)
        open_ports = probe_host_ports(ip_str, ports, timeout)
        with SUBNET_LOCK:
            SUBNET_SCANS[scan_id]["scanned_hosts"] += 1
            if open_ports:
                SUBNET_SCANS[scan_id]["hosts"].append({"ip": ip_str, "open_ports": open_ports})

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        list(executor.map(probe, hosts))

    with CANCEL_LOCK:
        was_cancelled = scan_id in CANCELLED_SCANS
        CANCELLED_SCANS.discard(scan_id)

    with SUBNET_LOCK:
        SUBNET_SCANS[scan_id]["status"] = "cancelled" if was_cancelled else "done"
        SUBNET_SCANS[scan_id]["finished_at"] = datetime.now().strftime("%H:%M:%S")
        SUBNET_SCANS[scan_id]["hosts"].sort(key=lambda h: ipaddress.ip_address(h["ip"]))


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/version", methods=["GET"])
def version():
    return jsonify({"version": VERSION})


@app.route("/api/resolve", methods=["POST"])
def resolve():
    data = request.get_json()
    raw_target = data.get("target", "").strip()
    if not raw_target:
        return jsonify({"error": "Hedef boş olamaz"}), 400

    hostname = extract_hostname(raw_target)
    if not hostname:
        return jsonify({"error": "Geçerli bir URL/domain/IP girin"}), 400

    result = advanced_resolve(hostname)
    if result["error"]:
        return jsonify({"error": result["error"]}), 400

    result["input"] = raw_target
    result["dns_engine"] = "dnspython" if HAS_DNSPYTHON else "socket (dnspython kurulu değil, sınırlı sonuç)"
    return jsonify(result)


@app.route("/api/ping", methods=["POST"])
def ping():
    data = request.get_json()
    target = data.get("target", "").strip()
    if not target:
        return jsonify({"error": "Hedef boş olamaz"}), 400
    try:
        ip = socket.gethostbyname(extract_hostname(target))
    except socket.gaierror:
        return jsonify({"error": f"'{target}' çözülemedi"}), 400

    result = ping_host(ip)
    result["ip"] = ip
    return jsonify(result)


@app.route("/api/scan/<scan_id>/cancel", methods=["POST"])
def cancel_scan(scan_id):
    with SCANS_LOCK:
        if scan_id not in SCANS:
            return jsonify({"error": "Tarama bulunamadı"}), 404
    with CANCEL_LOCK:
        CANCELLED_SCANS.add(scan_id)
    return jsonify({"cancelled": True})


@app.route("/api/history", methods=["GET"])
def get_history():
    with HISTORY_LOCK:
        return jsonify(list(SCAN_HISTORY))


@app.route("/api/scan/<scan_id>/export.<fmt>", methods=["GET"])
def export_scan(scan_id, fmt):
    with SCANS_LOCK:
        scan = SCANS.get(scan_id)
        if not scan:
            return jsonify({"error": "Tarama bulunamadı"}), 404
        scan = dict(scan)

    if fmt == "json":
        return Response(
            jsonify(scan).get_data(),
            mimetype="application/json",
            headers={"Content-Disposition": f"attachment; filename=scan_{scan_id[:8]}.json"}
        )
    elif fmt == "csv":
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["port", "service", "banner", "ssl_common_name", "ssl_issuer", "ssl_valid_until"])
        for p in scan.get("open_ports", []):
            ssl_info = p.get("ssl") or {}
            writer.writerow([
                p["port"], p["service"], p.get("banner", ""),
                ssl_info.get("common_name", ""), ssl_info.get("issuer", ""),
                ssl_info.get("valid_until", "")
            ])
        return Response(
            buf.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": f"attachment; filename=scan_{scan_id[:8]}.csv"}
        )
    else:
        return jsonify({"error": "Geçersiz format. json veya csv kullanın"}), 400


@app.route("/api/port-presets", methods=["GET"])
def port_presets():
    return jsonify(PORT_PRESETS)


@app.route("/api/whois", methods=["POST"])
def whois_endpoint():
    data = request.get_json()
    raw_target = data.get("target", "").strip()
    if not raw_target:
        return jsonify({"error": "Hedef boş olamaz"}), 400
    target = extract_hostname(raw_target)
    result = whois_lookup(target)
    if not result:
        return jsonify({"error": "WHOIS sorgusu başarısız oldu"}), 502
    return jsonify({"target": target, "raw": result[:6000]})


@app.route("/api/geoip", methods=["POST"])
def geoip_endpoint():
    data = request.get_json()
    target = data.get("target", "").strip()
    if not target:
        return jsonify({"error": "Hedef boş olamaz"}), 400
    try:
        ip = socket.gethostbyname(extract_hostname(target))
    except socket.gaierror:
        return jsonify({"error": f"'{target}' çözülemedi"}), 400
    info = geoip_lookup(ip)
    if not info:
        return jsonify({"error": "GeoIP bilgisi alınamadı"}), 502
    info["ip"] = ip
    return jsonify(info)


@app.route("/api/traceroute", methods=["POST"])
def traceroute_endpoint():
    data = request.get_json()
    target = data.get("target", "").strip()
    if not target:
        return jsonify({"error": "Hedef boş olamaz"}), 400
    try:
        ip = socket.gethostbyname(extract_hostname(target))
    except socket.gaierror:
        return jsonify({"error": f"'{target}' çözülemedi"}), 400
    output = traceroute_host(ip)
    if output is None:
        return jsonify({"error": "traceroute/tracert komutu çalıştırılamadı (sistemde kurulu olmayabilir)"}), 502
    return jsonify({"target": target, "ip": ip, "output": output})


@app.route("/api/subnet-scan", methods=["POST"])
def start_subnet_scan():
    data = request.get_json()
    cidr = data.get("cidr", "").strip()
    port_str = data.get("ports", PORT_PRESETS["web"]).strip()
    timeout = float(data.get("timeout", 0.4))

    if not cidr:
        return jsonify({"error": "CIDR boş olamaz"}), 400

    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return jsonify({"error": "Geçersiz CIDR. Örn: 192.168.1.0/24"}), 400

    if network.num_addresses > MAX_SUBNET_HOSTS + 2:
        return jsonify({"error": f"En fazla /24 (256 host) taranabilir"}), 400

    try:
        ports = parse_ports(port_str)
    except Exception:
        return jsonify({"error": "Port formatı geçersiz. Örn: 80,443,22"}), 400

    if not ports:
        return jsonify({"error": "Geçerli port bulunamadı"}), 400

    if len(ports) > MAX_SUBNET_PORTS:
        return jsonify({"error": f"Alt ağ taramasında en fazla {MAX_SUBNET_PORTS} port kullanılabilir"}), 400

    timeout = max(0.1, min(timeout, 2.0))

    scan_id = str(uuid.uuid4())
    with SUBNET_LOCK:
        SUBNET_SCANS[scan_id] = {
            "cidr": cidr,
            "total_hosts": 0,
            "scanned_hosts": 0,
            "hosts": [],
            "status": "running",
            "started_at": datetime.now().strftime("%H:%M:%S"),
            "finished_at": None
        }

    t = threading.Thread(target=run_subnet_scan, args=(scan_id, network, ports, timeout))
    t.daemon = True
    t.start()

    return jsonify({"scan_id": scan_id})


@app.route("/api/subnet-scan/<scan_id>", methods=["GET"])
def subnet_scan_status(scan_id):
    with SUBNET_LOCK:
        scan = SUBNET_SCANS.get(scan_id)
        if not scan:
            return jsonify({"error": "Tarama bulunamadı"}), 404
        return jsonify(dict(scan))


@app.route("/api/subnet-scan/<scan_id>/cancel", methods=["POST"])
def cancel_subnet_scan(scan_id):
    with SUBNET_LOCK:
        if scan_id not in SUBNET_SCANS:
            return jsonify({"error": "Tarama bulunamadı"}), 404
    with CANCEL_LOCK:
        CANCELLED_SCANS.add(scan_id)
    return jsonify({"cancelled": True})


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
        ip = socket.gethostbyname(extract_hostname(target))
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

    t = threading.Thread(target=run_scan, args=(scan_id, ip, extract_hostname(target), ports, threads, timeout))
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
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)

