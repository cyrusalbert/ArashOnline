#!/usr/bin/env python3
"""Build chained configs (entry -> exit) and publish them as a JSON subscription.

  * exits   : the fastest configs from lowest.txt
  * entries : random configs from entryconfs.txt (file path or URL)
Each exit is paired with one random entry. Every chain is tested end to end
(HTTP GET latency, exit country, download speed); a dead entry is replaced by
another random one. The result is written to chains.json, a JSON array of
full Xray configs whose "remarks" look like:  <exit flag> | <exit ip:port> <ping> <speed>

Traffic path:  you -> entry server -> exit server -> internet.
Needs select_lowest.py next to this file and the `xray` binary in PATH.
"""
from __future__ import annotations

import copy
import json
import os
import random
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Callable, Optional

import select_lowest as sl

# ----------------------------- settings ------------------------------------
EXIT_FILE = Path("lowest.txt")
ENTRY_SOURCE = os.environ.get("ENTRY_SOURCE", "entryconfs.txt")  # path or URL
OUTPUT_FILE = Path("chains.json")
N_CHAINS = 30
ENTRY_TRIES = 6          # random entries tried per exit before giving up on it
CHAIN_TIMEOUT = 12.0     # per-request timeout; chains have two hops
SPEED_URL = "https://speed.cloudflare.com/__down?bytes=25000000"
SPEED_SECONDS = 8.0      # how long the download test runs
MIN_SPEED_BYTES = 65536  # less than this counts as a failed speed test

sl.TIMEOUT = CHAIN_TIMEOUT  # sl.http_get reads this value at call time


# ----------------------------- loading -------------------------------------
def read_text(source: str) -> str:
    if source.lower().startswith(("http://", "https://")):
        req = urllib.request.Request(source, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.read().decode("utf-8-sig", errors="ignore")
    return Path(source).read_text(encoding="utf-8-sig", errors="ignore")


def parse_nodes(text: str) -> list[sl.Node]:
    if not any(s in text for s in sl.SCHEMES):
        try:  # maybe a base64 subscription
            text = sl.b64decode_loose(text).decode("utf-8", errors="ignore")
        except Exception:
            pass
    nodes, seen = [], set()
    for line in text.splitlines():
        line = line.strip()
        if not line.lower().startswith(sl.SCHEMES) or line in seen:
            continue
        seen.add(line)
        try:
            nodes.append(sl.parse_link(line))
        except Exception:
            pass  # unsupported or broken link: ignore
    return nodes


def can_be_exit(node: sl.Node) -> bool:
    # UDP-based transports cannot be dialed through another proxy
    return node.outbound.get("streamSettings", {}).get("network") != "kcp"


class EntryPool:
    """Thread-safe pool of shuffled entry nodes; each one is handed out once."""

    def __init__(self, nodes: list[sl.Node]):
        self._nodes = list(nodes)
        random.shuffle(self._nodes)
        self._lock = threading.Lock()

    def take(self, avoid_host: str) -> Optional[sl.Node]:
        with self._lock:
            for i, node in enumerate(self._nodes):
                if node.host != avoid_host:
                    return self._nodes.pop(i)
        return None


# ----------------------------- chains --------------------------------------
def chain_outbounds(entry: sl.Node, exit_: sl.Node) -> list[dict]:
    """Exit outbound dials its server through the entry outbound."""
    exit_ob = copy.deepcopy(exit_.outbound)
    exit_ob["tag"] = "proxy"
    exit_ob.setdefault("streamSettings", {}).setdefault("sockopt", {})["dialerProxy"] = "entry"
    entry_ob = copy.deepcopy(entry.outbound)
    entry_ob["tag"] = "entry"
    return [exit_ob, entry_ob]


def with_xray(outbounds: list[dict], tmp: Path, name: str, work: Callable[[int], object]):
    """Run a temporary Xray with these outbounds and return work(local_http_port)."""
    for attempt in range(2):  # retry once if the local port was taken meanwhile
        port = sl.alloc_port()
        cfg = {
            "log": {"loglevel": "none"},
            "inbounds": [{"tag": "in", "listen": "127.0.0.1", "port": port,
                          "protocol": "http", "settings": {}}],
            "outbounds": outbounds,
        }
        path = tmp / f"{name}_{attempt}.json"
        path.write_text(json.dumps(cfg), encoding="utf-8")
        proc = subprocess.Popen([sl.XRAY, "run", "-c", str(path)],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            ready = sl.wait_ready(proc, port)
            if ready is False:
                continue
            if not ready:
                return None
            return work(port)
        finally:
            sl.stop(proc)
            sl.release_port(port)
    return None


def probe(port: int):
    latency = sl.measure_latency(port)
    if latency is None:
        return None
    return latency, sl.lookup_country(port)


def measure_speed(port: int) -> Optional[float]:
    """Download for SPEED_SECONDS through the proxy and return Mbps (or None)."""
    proxy = f"http://127.0.0.1:{port}"
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    req = urllib.request.Request(SPEED_URL, headers={"User-Agent": "Mozilla/5.0"})
    total, start = 0, None
    try:
        with opener.open(req, timeout=sl.TIMEOUT) as resp:
            if resp.getcode() != 200:
                return None
            start = time.perf_counter()
            while time.perf_counter() - start < SPEED_SECONDS:
                chunk = resp.read(65536)
                if not chunk:
                    break
                total += len(chunk)
    except Exception:
        pass  # keep whatever was downloaded before the error
    if start is None or total < MIN_SPEED_BYTES:
        return None
    elapsed = max(time.perf_counter() - start, 0.001)
    return total * 8 / elapsed / 1e6


def build_chain(idx: int, exit_: sl.Node, pool: EntryPool, tmp: Path):
    """Find a working entry for this exit. Returns (entry, latency, country) or None."""
    try:
        for attempt in range(ENTRY_TRIES):
            entry = pool.take(exit_.host)
            if entry is None:
                return None
            res = with_xray(chain_outbounds(entry, exit_), tmp, f"c{idx}_{attempt}", probe)
            if res:
                return entry, res[0], res[1]
        return None
    except Exception as exc:  # one bad chain must not stop the run
        print(f"  error on exit {exit_.host}:{exit_.port}: {exc}")
        return None


# ----------------------------- output --------------------------------------
def make_remark(country: Optional[str], exit_: sl.Node, ping: float, speed: Optional[float]) -> str:
    ip = sl.resolve_ip(exit_.host)
    addr = f"[{ip}]" if ":" in ip else ip
    speed_txt = f"{speed:.1f}Mbps" if speed else "n/a"
    return f"{sl.country_flag(country)} | {addr}:{exit_.port} {ping:.0f}ms {speed_txt}"


def client_config(remark: str, outbounds: list[dict]) -> dict:
    """Full Xray client config (same local ports v2rayN / v2rayNG use by default)."""
    return {
        "remarks": remark,
        "log": {"loglevel": "warning"},
        "dns": {"servers": ["1.1.1.1", "8.8.8.8"]},
        "inbounds": [
            {"tag": "socks", "listen": "127.0.0.1", "port": 10808, "protocol": "socks",
             "settings": {"auth": "noauth", "udp": True},
             "sniffing": {"enabled": True, "destOverride": ["http", "tls"]}},
            {"tag": "http", "listen": "127.0.0.1", "port": 10809, "protocol": "http",
             "settings": {}},
        ],
        "outbounds": outbounds + [
            {"tag": "direct", "protocol": "freedom", "settings": {}},
            {"tag": "block", "protocol": "blackhole", "settings": {}},
        ],
        "routing": {"domainStrategy": "AsIs", "rules": []},
    }


# ----------------------------- main ----------------------------------------
def main() -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # emoji-safe on Windows
    except Exception:
        pass
    if not sl.XRAY:
        print("xray not found: put it in PATH or set XRAY_PATH")
        return 2
    try:
        exits = [n for n in parse_nodes(read_text(str(EXIT_FILE))) if can_be_exit(n)]
    except OSError as exc:
        print(f"cannot read {EXIT_FILE}: {exc}")
        return 2
    try:
        entries = parse_nodes(read_text(ENTRY_SOURCE))
    except Exception as exc:
        print(f"cannot read {ENTRY_SOURCE}: {exc}")
        return 2
    if not exits or not entries:
        print(f"need usable configs in both files (exits: {len(exits)}, entries: {len(entries)})")
        return 2
    print(f"{len(exits)} exit candidates, {len(entries)} entry candidates")

    pool = EntryPool(entries)
    chains = []  # (exit, entry, latency, country)
    queue, idx = list(exits), 0
    with tempfile.TemporaryDirectory() as tmp, ThreadPoolExecutor(max_workers=sl.WORKERS) as ex:
        tmp_path = Path(tmp)
        # Test exits fastest-first; if some fail, move on to the next ones.
        while len(chains) < N_CHAINS and queue:
            batch, queue = queue[:N_CHAINS - len(chains)], queue[N_CHAINS - len(chains):]
            futures = [ex.submit(build_chain, idx + i, e, pool, tmp_path)
                       for i, e in enumerate(batch)]
            idx += len(batch)
            for e, fut in zip(batch, futures):
                res = fut.result()
                if res:
                    chains.append((e, res[0], res[1], res[2]))
                else:
                    print(f"no working entry for exit {e.host}:{e.port}")

        if not chains:
            print("no working chains; keeping the old output file")
            return 1

        # Speed tests run one at a time so they don't disturb each other.
        configs = []
        for n, (e, entry, latency, country) in enumerate(chains):
            outbounds = chain_outbounds(entry, e)
            speed = with_xray(outbounds, tmp_path, f"s{n}", measure_speed)
            configs.append((latency, make_remark(country, e, latency, speed), outbounds))

    configs.sort(key=lambda c: c[0])
    for _, remark, _ in configs:
        print(remark)
    OUTPUT_FILE.write_text(
        json.dumps([client_config(r, o) for _, r, o in configs], ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8")
    print(f"Saved {len(configs)} chains to {OUTPUT_FILE}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
