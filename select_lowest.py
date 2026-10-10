#!/usr/bin/env python3
"""Test v2ray links through Xray and keep the lowest-latency ones.

For every link in configs.txt:
  1. start a temporary Xray client for it (local HTTP proxy)
  2. measure HTTP GET latency through that proxy (median of several requests)
  3. look up the exit IP's country through the same proxy
The TOP_N fastest are renamed to "<flag> |<ip>:<port>" and saved to lowest.txt.

Needs the `xray` binary in PATH (or set XRAY_PATH). Standard library only.
Supported links: vless://, vmess://, trojan://, ss://
"""
from __future__ import annotations

import base64
import ipaddress
import json
import os
import re
import shutil
import socket
import statistics
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from urllib.parse import parse_qs, quote, unquote, urlsplit

# ----------------------------- settings ------------------------------------
INPUT_FILE = Path("configs.txt")
OUTPUT_FILE = Path("lowest.txt")
TOP_N = 20
TEST_URL = "http://cp.cloudflare.com/generate_204"
SAMPLES = 3            # timed requests per config (after one warm-up request)
MIN_OK = 2             # successful timed requests needed to count as alive
TIMEOUT = 8.0          # seconds per request
START_TIMEOUT = 8.0    # seconds to wait for Xray to start listening
WORKERS = 8            # configs tested in parallel
XRAY = os.environ.get("XRAY_PATH") or shutil.which("xray")

GEO_APIS = [
    ("http://ip-api.com/json/?fields=status,countryCode",
     lambda d: d.get("countryCode") if d.get("status") == "success" else None),
    ("https://ipwho.is/",
     lambda d: d.get("country_code") if d.get("success") else None),
]

SCHEMES = ("vless://", "vmess://", "trojan://", "ss://")
NET_ALIASES = {"raw": "tcp", "h2": "http", "splithttp": "xhttp", "mkcp": "kcp"}


@dataclass
class Node:
    link: str
    host: str
    port: int
    outbound: dict


# ----------------------------- parsing -------------------------------------
def b64decode_loose(text: str) -> bytes:
    """Decode standard or URL-safe base64, with or without padding."""
    text = "".join(text.split()).replace("-", "+").replace("_", "/")
    text += "=" * (-len(text) % 4)
    return base64.b64decode(text, validate=True)


def load_links(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8-sig", errors="ignore")
    if not any(s in text for s in SCHEMES):
        try:  # maybe the whole file is a base64 subscription
            text = b64decode_loose(text).decode("utf-8", errors="ignore")
        except Exception:
            pass
    links, seen = [], set()
    for line in text.splitlines():
        line = line.strip()
        if line.lower().startswith(SCHEMES) and line not in seen:
            seen.add(line)
            links.append(line)
    return links


def build_stream(net: str, security: str, p: dict) -> dict:
    net = (net or "tcp").lower()
    net = NET_ALIASES.get(net, net)
    security = (security or "none").lower()
    host, path = p["host"], p["path"]
    hosts = [h.strip() for h in host.split(",") if h.strip()]
    stream: dict = {"network": net, "security": security}

    if net == "tcp":
        if p["header_type"] == "http":
            request: dict = {"path": [x for x in (path or "/").split(",") if x] or ["/"]}
            if hosts:
                request["headers"] = {"Host": hosts}
            stream["tcpSettings"] = {"header": {"type": "http", "request": request}}
    elif net == "ws":
        ws: dict = {"path": path or "/"}
        if host:
            ws["headers"] = {"Host": host}
        stream["wsSettings"] = ws
    elif net == "grpc":
        grpc: dict = {"serviceName": p["service_name"], "multiMode": p["mode"] == "multi"}
        if p["authority"]:
            grpc["authority"] = p["authority"]
        stream["grpcSettings"] = grpc
    elif net == "http":
        stream["httpSettings"] = {"path": path or "/", "host": hosts}
    elif net == "httpupgrade":
        stream["httpupgradeSettings"] = {"path": path or "/", "host": host}
    elif net == "xhttp":
        xh: dict = {"path": path or "/", "mode": p["mode"] or "auto"}
        if host:
            xh["host"] = host
        if p["extra"]:
            try:
                xh["extra"] = json.loads(p["extra"])
            except ValueError:
                pass
        stream["xhttpSettings"] = xh
    elif net == "kcp":
        kcp: dict = {"header": {"type": p["header_type"] or "none"}}
        if p["seed"]:
            kcp["seed"] = p["seed"]
        stream["kcpSettings"] = kcp
    else:
        raise ValueError(f"unsupported transport '{net}'")

    sni = p["sni"]
    if not sni and hosts and net in ("ws", "http", "httpupgrade", "xhttp"):
        sni = hosts[0]

    if security == "tls":
        tls: dict = {"allowInsecure": p["insecure"]}
        if sni:
            tls["serverName"] = sni
        if p["fp"]:
            tls["fingerprint"] = p["fp"]
        if p["alpn"]:
            tls["alpn"] = p["alpn"]
        stream["tlsSettings"] = tls
    elif security == "reality":
        if not p["pbk"]:
            raise ValueError("reality link without public key")
        reality = {
            "serverName": p["sni"],
            "fingerprint": p["fp"] or "chrome",
            "publicKey": p["pbk"],
            "shortId": p["sid"],
            "spiderX": p["spx"],
        }
        if p["pqv"]:
            reality["mldsa65Verify"] = p["pqv"]
        stream["realitySettings"] = reality
    elif security != "none":
        raise ValueError(f"unsupported security '{security}'")
    return stream


def parse_url_style(link: str, scheme: str) -> Node:
    """vless:// and trojan://"""
    parts = urlsplit(link)
    host, port = parts.hostname, parts.port
    if not host or not port:
        raise ValueError("missing host or port")
    secret = unquote(parts.netloc.rpartition("@")[0])
    if not secret:
        raise ValueError("missing id/password")
    q = parse_qs(parts.query)

    def g(key: str, default: str = "") -> str:
        return (q.get(key) or [default])[0]

    p = {
        "host": g("host"), "path": g("path"), "header_type": g("headerType"),
        "service_name": g("serviceName"), "mode": g("mode"),
        "authority": g("authority"), "seed": g("seed"),
        "sni": g("sni") or g("peer"), "fp": g("fp"),
        "alpn": [a for a in g("alpn").split(",") if a],
        "insecure": (g("allowInsecure") or g("insecure")).lower() in ("1", "true"),
        "pbk": g("pbk"), "sid": g("sid"), "spx": g("spx"), "pqv": g("pqv"),
        "extra": g("extra"),
    }
    stream = build_stream(g("type", "tcp"), g("security", "tls" if scheme == "trojan" else "none"), p)

    if scheme == "vless":
        user = {"id": secret, "encryption": g("encryption", "none")}
        if g("flow"):
            user["flow"] = g("flow")
        settings = {"vnext": [{"address": host, "port": port, "users": [user]}]}
    else:
        settings = {"servers": [{"address": host, "port": port, "password": secret}]}
    outbound = {"protocol": scheme, "settings": settings, "streamSettings": stream}
    return Node(link, host, port, outbound)


def parse_vmess(link: str) -> Node:
    payload = link.split("://", 1)[1].split("#", 1)[0]
    data = json.loads(b64decode_loose(payload).decode("utf-8"))

    def s(key: str) -> str:
        return str(data.get(key) or "")

    host, port = s("add"), int(data.get("port") or 0)
    if not host or not port or not s("id"):
        raise ValueError("missing host, port or id")
    net = (s("net") or "tcp").lower()
    typ, path = s("type"), s("path")
    p = {
        "host": s("host"), "path": path,
        "header_type": typ if net in ("tcp", "kcp", "raw", "mkcp") else "",
        "service_name": path if net == "grpc" else "",
        "mode": typ if net in ("grpc", "xhttp", "splithttp") else "",
        "authority": "", "seed": path if net in ("kcp", "mkcp") else "",
        "sni": s("sni"), "fp": s("fp"),
        "alpn": [a for a in s("alpn").split(",") if a],
        "insecure": (s("allowInsecure") or s("insecure")).lower() in ("1", "true"),
        "pbk": "", "sid": "", "spx": "", "pqv": "", "extra": "",
    }
    security = "tls" if s("tls").lower() == "tls" else "none"
    user = {"id": s("id"), "alterId": int(data.get("aid") or 0), "security": s("scy") or "auto"}
    outbound = {
        "protocol": "vmess",
        "settings": {"vnext": [{"address": host, "port": port, "users": [user]}]},
        "streamSettings": build_stream(net, security, p),
    }
    return Node(link, host, port, outbound)


def parse_ss(link: str) -> Node:
    main = link[len("ss://"):].split("#", 1)[0]
    main, _, query = main.partition("?")
    main = main.rstrip("/")
    if "plugin=" in query:
        raise ValueError("shadowsocks plugins are not supported")
    if "@" in main:
        userinfo, _, hostport = main.rpartition("@")
        if re.fullmatch(r"[A-Za-z0-9_\-+/=]+", userinfo):
            creds = b64decode_loose(userinfo).decode("utf-8")
        else:
            creds = unquote(userinfo)
    else:  # legacy form: base64(method:password@host:port)
        decoded = b64decode_loose(main).decode("utf-8")
        creds, _, hostport = decoded.rpartition("@")
    method, _, password = creds.partition(":")
    host, _, port_s = hostport.rpartition(":")
    host = host.strip("[]")
    if not host or not port_s.isdigit() or not method or not password:
        raise ValueError("malformed ss link")
    port = int(port_s)
    outbound = {
        "protocol": "shadowsocks",
        "settings": {"servers": [{"address": host, "port": port,
                                  "method": method, "password": password}]},
    }
    return Node(link, host, port, outbound)


def parse_link(link: str) -> Node:
    scheme = link.split("://", 1)[0].lower()
    if scheme in ("vless", "trojan"):
        return parse_url_style(link, scheme)
    if scheme == "vmess":
        return parse_vmess(link)
    if scheme == "ss":
        return parse_ss(link)
    raise ValueError(f"unsupported scheme '{scheme}'")


# ----------------------------- renaming ------------------------------------
def country_flag(code: Optional[str]) -> str:
    code = (code or "").upper()
    if len(code) == 2 and code.isascii() and code.isalpha():
        return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in code)
    return "\U0001F310"  # globe when the country is unknown


def resolve_ip(host: str) -> str:
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError:
        return host
    for info in infos:
        if info[0] == socket.AF_INET:
            return info[4][0]
    return infos[0][4][0] if infos else host


def make_name(country: Optional[str], ip: str, port: int) -> str:
    addr = f"[{ip}]" if ":" in ip else ip
    return f"{country_flag(country)} |{addr}:{port}"


def rename_link(link: str, name: str) -> str:
    scheme, _, rest = link.partition("://")
    if scheme.lower() == "vmess":
        data = json.loads(b64decode_loose(rest.split("#", 1)[0]).decode("utf-8"))
        data["ps"] = name
        raw = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        return "vmess://" + base64.b64encode(raw).decode("ascii")
    return link.split("#", 1)[0] + "#" + quote(name, safe="")


# ----------------------------- testing -------------------------------------
_port_lock = threading.Lock()
_used_ports: set[int] = set()


def alloc_port() -> int:
    with _port_lock:
        for _ in range(100):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                s.bind(("127.0.0.1", 0))
                port = s.getsockname()[1]
            finally:
                s.close()
            if port not in _used_ports:
                _used_ports.add(port)
                return port
    raise RuntimeError("no free local port")


def release_port(port: int) -> None:
    with _port_lock:
        _used_ports.discard(port)


def http_get(url: str, proxy_port: int):
    proxy = f"http://127.0.0.1:{proxy_port}"
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    start = time.perf_counter()
    with opener.open(req, timeout=TIMEOUT) as resp:
        body = resp.read(65536)
        status = resp.getcode()
    return status, body, (time.perf_counter() - start) * 1000


def measure_latency(proxy_port: int) -> Optional[float]:
    try:  # warm-up: also the aliveness check, not timed
        if http_get(TEST_URL, proxy_port)[0] not in (200, 204):
            return None
    except Exception:
        return None
    times = []
    for _ in range(SAMPLES):
        try:
            status, _, ms = http_get(TEST_URL, proxy_port)
            if status in (200, 204):
                times.append(ms)
        except Exception:
            pass
    return statistics.median(times) if len(times) >= MIN_OK else None


def lookup_country(proxy_port: int) -> Optional[str]:
    for url, extract in GEO_APIS:
        try:
            _, body, _ = http_get(url, proxy_port)
            code = extract(json.loads(body.decode("utf-8", errors="ignore")))
            if code:
                return str(code)
        except Exception:
            continue
    return None


def wait_ready(proc: subprocess.Popen, port: int) -> Optional[bool]:
    """True = listening, False = Xray exited early, None = timed out."""
    deadline = time.monotonic() + START_TIMEOUT
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            return False
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
            return True
        except OSError:
            time.sleep(0.1)
    return None


def stop(proc: subprocess.Popen) -> None:
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


def test_node(idx: int, node: Node, tmp: Path):
    """Return (latency_ms, country_code) or None if the config is dead."""
    try:
        for attempt in range(2):  # retry once if the local port was stolen
            port = alloc_port()
            cfg = {
                "log": {"loglevel": "none"},
                "inbounds": [{"tag": "in", "listen": "127.0.0.1", "port": port,
                              "protocol": "http", "settings": {}}],
                "outbounds": [dict(node.outbound, tag="proxy")],
            }
            cfg_path = tmp / f"{idx}_{attempt}.json"
            cfg_path.write_text(json.dumps(cfg), encoding="utf-8")
            proc = subprocess.Popen([XRAY, "run", "-c", str(cfg_path)],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                ready = wait_ready(proc, port)
                if ready is False:
                    continue
                if not ready:
                    return None
                latency = measure_latency(port)
                if latency is None:
                    return None
                return latency, lookup_country(port)
            finally:
                stop(proc)
                release_port(port)
        return None
    except Exception as exc:  # never let one config crash the whole run
        print(f"  error testing {node.host}:{node.port}: {exc}")
        return None


# ----------------------------- main ----------------------------------------
def main() -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # emoji-safe on Windows
    except Exception:
        pass
    if not XRAY:
        print("xray not found: put it in PATH or set XRAY_PATH")
        return 2
    if not INPUT_FILE.exists():
        print(f"{INPUT_FILE} not found")
        return 2

    nodes: list[Node] = []
    for link in load_links(INPUT_FILE):
        try:
            nodes.append(parse_link(link))
        except Exception as exc:
            print(f"skipped ({exc}): {link[:50]}...")
    if not nodes:
        print("no usable links found")
        return 2
    print(f"Testing {len(nodes)} configs with {WORKERS} workers...")

    with tempfile.TemporaryDirectory() as tmp, ThreadPoolExecutor(max_workers=WORKERS) as pool:
        results = list(pool.map(lambda a: test_node(a[0], a[1], Path(tmp)), enumerate(nodes)))

    alive = [(r[0], r[1], n) for r, n in zip(results, nodes) if r]
    print(f"{len(alive)} of {len(nodes)} configs are alive")
    if not alive:
        print("nothing works; keeping the old output file")
        return 1

    alive.sort(key=lambda x: x[0])
    lines = []
    for latency, country, node in alive[:TOP_N]:
        name = make_name(country, resolve_ip(node.host), node.port)
        lines.append(rename_link(node.link, name))
        print(f"{latency:7.0f} ms  {name}")

    OUTPUT_FILE.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Saved {len(lines)} configs to {OUTPUT_FILE}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
