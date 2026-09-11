#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Sync networks announced by a set of ASNs (via RIPEstat) plus resolved DNS
names into one of two targets:

  netbird   - create / delete routes through the NetBird API
  wireguard - keep a route file (one CIDR per line) in sync and add / delete
              kernel routes on the WireGuard interface

Target is selected with --target or `target:` in the config file.
"""
import argparse
import bisect
import os
import queue
import socket
import subprocess
import sys
import threading
from os.path import expanduser

import requests
import yaml
from netaddr import IPNetwork, IPSet, cidr_merge, spanning_cidr

RIPE_ANNOUNCED_URL = "https://stat.ripe.net/data/announced-prefixes/data.json"
NETBIRD_MARKER = "Managed by RIPE sync:"
WG_FILE_HEADER = "# Managed by sync-ripe-routes - do not edit by hand"


# config {{
def load_config(explicit_path=None):
    """Loads the first readable YAML config from the candidate list."""
    script_name = os.path.basename(sys.argv[0]).split('.')[0]
    script_dir = os.path.dirname(os.path.abspath(__file__))
    if explicit_path:
        candidates = [explicit_path]
    else:
        candidates = [
            os.path.join(expanduser("~"), f".{script_name}.yaml"),
            os.path.join(os.getcwd(), '.config.yaml'),
            os.path.join(script_dir, '.config.yaml'),
        ]
    for config_file in candidates:
        if not os.path.isfile(config_file):
            continue
        try:
            with open(config_file, 'r') as fh:
                return yaml.safe_load(fh) or {}
        except Exception as e:
            print(f"config: skipping '{config_file}': {e}")
    sys.exit(f"config: no readable config file found in {candidates}")
# }}


def run_workers(worker_fn, items, num_workers):
    """
    Plain worker pool: `num_workers` threads pull items off a shared queue and
    call worker_fn(item) until it is empty. Returns (results, errors).
    """
    q = queue.Queue()
    for item in items:
        q.put(item)

    results = []
    errors = []
    lock = threading.Lock()

    def worker():
        while True:
            try:
                item = q.get_nowait()
            except queue.Empty:
                return
            try:
                result = worker_fn(item)
                with lock:
                    results.append(result)
            except Exception as e:
                with lock:
                    errors.append((item, e))
            finally:
                q.task_done()

    threads = [threading.Thread(target=worker) for _ in range(min(num_workers, len(items)) or 1)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return results, errors


# collecting prefixes {{
def fetch_asn_prefixes(asn):
    """Fetches announced prefixes for one ASN from the RIPEstat API."""
    r = requests.get(RIPE_ANNOUNCED_URL, params={"resource": asn}, timeout=30)
    r.raise_for_status()
    return asn, [p["prefix"] for p in r.json()["data"]["prefixes"]]


def resolve_hostname(hostname):
    """Resolves a hostname to a list of unique IPs (v4 and v6)."""
    ips = []
    try:
        for info in socket.getaddrinfo(hostname, None):
            ip = info[4][0]
            if ip not in ips:
                ips.append(ip)
    except socket.gaierror as e:
        print(f"dns: cannot resolve {hostname}: {e}")
    return ips


def aggregate_lossy(networks, min_fill):
    """
    Folds neighbouring networks into their common supernet whenever that
    supernet would be filled by real prefixes to at least `min_fill` (0..1).
    This ADDS address space that was never announced, so only use it when
    routing a bit extra through the tunnel is acceptable.
    """
    items = [(net, net.size) for net in cidr_merge(networks)]
    changed = True
    while changed:
        changed = False
        out = []
        i = 0
        while i < len(items):
            if i + 1 < len(items) and items[i][0].version == items[i + 1][0].version:
                (a, real_a), (b, real_b) = items[i], items[i + 1]
                supernet = spanning_cidr([a, b])
                if (real_a + real_b) / supernet.size >= min_fill:
                    out.append((supernet, real_a + real_b))
                    i += 2
                    changed = True
                    continue
            out.append(items[i])
            i += 1
        items = out
    return [net for net, _ in items]


def build_desired(cfg, ripe_threads):
    """
    Returns an ordered dict {prefix_str: [sources]} - the final list of
    networks that should be routed, and which ASNs / dns_names contributed
    to each of them.
    """
    ipv4_only = cfg.get('ipv4_only', False)
    excludes = IPSet(cfg.get('exclude') or [])
    min_fill = (cfg.get('aggregate') or {}).get('min_fill')

    # raw (source, network) pairs
    raw = []
    fetch_results, fetch_errors = run_workers(fetch_asn_prefixes, cfg.get('asns') or [], ripe_threads)
    for asn, e in fetch_errors:
        print(f"ripe: error fetching prefixes for {asn}: {e}")
    for asn, prefixes in fetch_results:
        raw.extend((str(asn), IPNetwork(p)) for p in prefixes)
    for hostname in cfg.get('dns_names') or []:
        raw.extend(('dns_names', IPNetwork(ip)) for ip in resolve_hostname(hostname))

    if ipv4_only:
        raw = [(src, net) for src, net in raw if net.version == 4]

    # merge everything globally: sibling blocks from different ASNs fold into
    # one, and /32s from dns_names already covered by an ASN prefix disappear
    merged = cidr_merge([net for _, net in raw])
    print(f"prefixes: {len(raw)} raw -> {len(merged)} after exact merge")

    if min_fill:
        merged = aggregate_lossy(merged, float(min_fill))
        print(f"prefixes: {len(merged)} after lossy aggregation (min_fill={min_fill})")

    if excludes:
        merged = (IPSet(merged) - excludes).iter_cidrs()
        print(f"prefixes: {len(merged)} after excludes")

    # map every final network back to the sources that landed inside it;
    # final networks are disjoint, so the one with the largest `first`
    # <= net.first is the only candidate container
    final = sorted(merged)
    firsts = [net.first for net in final]
    sources = {net: set() for net in final}
    for src, net in raw:
        idx = bisect.bisect_right(firsts, net.first) - 1
        if idx >= 0 and net in final[idx]:
            sources[final[idx]].add(src)

    return {str(net): sorted(sources[net]) for net in final}
# }}


# netbird target {{
def sync_netbird(cfg, desired, threads, dry_run):
    nb = cfg['netbird']
    session = requests.Session()
    session.headers.update({
        "Authorization": f"Token {nb['token']}",
        "Content-Type": "application/json",
    })
    # pool must be able to serve `threads` concurrent requests (default is 10)
    adapter = requests.adapters.HTTPAdapter(pool_connections=threads, pool_maxsize=threads)
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    routes = session.get(f"{nb['api_url']}/routes")
    routes.raise_for_status()
    existing = {}
    for route in routes.json():
        network = route.get("network")
        if network:
            existing[str(IPNetwork(network))] = route

    to_create = [prefix for prefix in desired if prefix not in existing]
    to_delete = [
        (prefix, route) for prefix, route in existing.items()
        if route.get("description", "").startswith(NETBIRD_MARKER) and prefix not in desired
    ]
    print(f"netbird: {len(existing)} existing, {len(to_create)} to create, {len(to_delete)} to delete")

    def create_route(prefix):
        print(f"netbird: creating route {prefix}")
        if dry_run:
            return prefix
        response = session.post(
            f"{nb['api_url']}/routes",
            json={
                "network": prefix,
                "peer": nb['peer_id'],
                "network_id": prefix.replace("/", "-"),
                "enabled": True,
                "metric": cfg['route']['metric'],
                "groups": cfg['route']['groups'],
                "description": f"{NETBIRD_MARKER} route to {prefix} for asn {','.join(desired[prefix])}",
                "masquerade": cfg['route']['masquerade'],
            },
        )
        response.raise_for_status()
        return prefix

    def delete_route(item):
        prefix, route = item
        print(f"netbird: deleting obsolete route {prefix} ({route['id']})")
        if dry_run:
            return prefix
        response = session.delete(f"{nb['api_url']}/routes/{route['id']}")
        response.raise_for_status()
        return prefix

    _, errors = run_workers(create_route, to_create, threads)
    for prefix, e in errors:
        print(f"netbird: error creating route {prefix}: {e}")

    _, errors = run_workers(delete_route, to_delete, threads)
    for (prefix, _), e in errors:
        print(f"netbird: error deleting route {prefix}: {e}")
# }}


# wireguard target {{
def read_route_file(path):
    """Reads CIDRs from the route file, skipping blanks and '#' comments."""
    networks = []
    if not os.path.isfile(path):
        return networks
    with open(path, 'r') as fh:
        for line in fh:
            line = line.split('#', 1)[0].strip()
            if line:
                networks.append(str(IPNetwork(line)))
    return networks


def write_route_file(path, networks):
    """Atomically rewrites the route file."""
    tmp_path = path + '.tmp'
    with open(tmp_path, 'w') as fh:
        fh.write(WG_FILE_HEADER + "\n")
        for network in networks:
            fh.write(network + "\n")
    os.replace(tmp_path, path)


def ip_route(action, prefix, interface, dry_run):
    """Runs `ip route <action> <prefix> dev <interface>`; failures are logged, not raised."""
    cmd = ["ip", "route", action, prefix, "dev", interface]
    print(f"wireguard: {' '.join(cmd)}")
    if dry_run:
        return
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"wireguard: '{' '.join(cmd)}' failed: {result.stderr.strip()}")


def sync_wireguard(cfg, desired, dry_run):
    wg = cfg.get('wireguard') or {}
    path = wg.get('file', '/etc/wireguard/via-amsnl1.txt')
    interface = wg.get('interface', 'wg0')

    current = set(read_route_file(path))
    wanted = set(desired)
    to_delete = sorted(current - wanted, key=IPNetwork)
    to_add = sorted(wanted - current, key=IPNetwork)
    print(f"wireguard: {len(current)} in {path}, {len(to_add)} to add, {len(to_delete)} to delete")

    for prefix in to_delete:
        ip_route("del", prefix, interface, dry_run)
    for prefix in to_add:
        # drop this loop if new networks are only meant to be picked up on
        # the next interface restart (e.g. via PostUp reading the file)
        ip_route("replace", prefix, interface, dry_run)

    if (to_add or to_delete) and not dry_run:
        write_route_file(path, sorted(wanted, key=IPNetwork))
        print(f"wireguard: wrote {len(wanted)} networks to {path}")
# }}


def main():
    parser = argparse.ArgumentParser(description="Sync RIPE-announced networks into NetBird or a WireGuard route file")
    parser.add_argument("--config", help="path to YAML config (default: ~/.<script>.yaml, ./.config.yaml, <script dir>/.config.yaml)")
    parser.add_argument("--target", choices=["netbird", "wireguard"], help="sync target (overrides `target:` from config)")
    parser.add_argument("--dry-run", action="store_true", help="only print what would be changed")
    args = parser.parse_args()

    cfg = load_config(args.config)
    target = args.target or cfg.get('target')
    if target not in ("netbird", "wireguard"):
        sys.exit("target must be 'netbird' or 'wireguard' (use --target or `target:` in config)")

    # ripe: { threads: N } - defaults to 5; netbird: { threads: N } - defaults to 20
    ripe_threads = (cfg.get('ripe') or {}).get('threads', 5)
    netbird_threads = (cfg.get('netbird') or {}).get('threads', 20)

    desired = build_desired(cfg, ripe_threads)
    print(f"prefixes: {len(desired)} networks to route")

    if target == "netbird":
        sync_netbird(cfg, desired, netbird_threads, args.dry_run)
    else:
        sync_wireguard(cfg, desired, args.dry_run)


if __name__ == "__main__":
    main()
