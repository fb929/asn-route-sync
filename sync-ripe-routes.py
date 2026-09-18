#!/usr/bin/env python3
"""
Sync networks announced by a set of ASNs (via RIPEstat) plus resolved DNS
names into one of two targets:

  netbird   - create / delete routes through the NetBird API
  wireguard - keep a route file (one CIDR per line) in sync and add / delete
              kernel routes on the WireGuard interface

Target is selected with --target or `target:` in the config file.

Config reference (all keys except `asns` / target credentials are optional):

  target: wireguard
  asns: [AS60068, 212238]
  dns_names: [example.com]
  exclude: [10.0.0.0/8]          # always put the tunnel endpoint IP here
  ipv4_only: true
  aggregate: { min_fill: 0.8 }
  ripe:
    threads: 5
    timeout: 30
    min_peers_seeing: 0          # RIPEstat default is 10, which hides
                                 # regionally announced prefixes
  netbird: { api_url: ..., token: ..., peer_id: ..., threads: 20 }
  route: { groups: [...], metric: 9999, masquerade: true }
  wireguard:
    file: /etc/wireguard/via-amsnl1.txt
    interface: wg0
    apply_routes: true           # false = only maintain the file
"""
import argparse
import bisect
import json
import logging
import os
import socket
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

import requests
import yaml
from netaddr import IPNetwork, IPSet, cidr_merge
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

RIPE_ANNOUNCED_URL = "https://stat.ripe.net/data/announced-prefixes/data.json"
RIPE_SOURCE_APP = "sync-ripe-routes"
NETBIRD_MARKER = "Managed by RIPE sync:"
NETBIRD_TIMEOUT = 30
NETBIRD_NETWORK_ID_MAX_LENGTH = 40
WG_FILE_HEADER = "# Managed by sync-ripe-routes - do not edit by hand"
DNS_SOURCE = "dns_names"

log = logging.getLogger("sync-ripe-routes")


class SyncError(Exception):
    """Fatal, user-facing error: printed without a traceback, exit code 1."""


# config {{
def load_config(explicit_path=None):
    """
    Loads the first existing YAML config from the candidate list. A config
    that exists but cannot be parsed is fatal: silently falling through to
    another file with a different ASN list would wipe the current routes.
    """
    script_name = os.path.basename(sys.argv[0]).split('.')[0]
    script_dir = os.path.dirname(os.path.abspath(__file__))
    if explicit_path:
        candidates = [explicit_path]
    else:
        candidates = [
            os.path.join(os.path.expanduser("~"), f".{script_name}.yaml"),
            os.path.join(os.getcwd(), '.config.yaml'),
            os.path.join(script_dir, '.config.yaml'),
        ]
    for config_file in candidates:
        if not os.path.isfile(config_file):
            continue
        try:
            with open(config_file, 'r') as fh:
                cfg = yaml.safe_load(fh) or {}
        except (OSError, yaml.YAMLError) as e:
            raise SyncError(f"config: cannot load '{config_file}': {e}")
        if not isinstance(cfg, dict):
            raise SyncError(f"config: '{config_file}' must contain a YAML mapping")
        log.info("config: using %s", config_file)
        return cfg
    raise SyncError(f"config: no config file found in {candidates}")


def section(cfg, name):
    """Returns a config sub-mapping, tolerating a missing or empty key."""
    return cfg.get(name) or {}


def require(mapping, mapping_name, keys):
    missing = [key for key in keys if mapping.get(key) in (None, "", [])]
    if missing:
        raise SyncError(f"config: missing {mapping_name}.{{{','.join(missing)}}}")
# }}


# helpers {{
def make_session(pool_size, headers=None):
    """requests session with a connection pool sized for `pool_size` threads and retries."""
    session = requests.Session()
    if headers:
        session.headers.update(headers)
    # retries cover connection errors and 429/5xx for idempotent methods only,
    # so a POST is never replayed
    retry = Retry(total=4, backoff_factor=1, status_forcelist=(429, 500, 502, 503, 504))
    adapter = HTTPAdapter(pool_connections=pool_size, pool_maxsize=pool_size, max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def run_parallel(fn, items, max_workers):
    """Calls fn(item) in a thread pool. Returns (results, [(item, exception), ...])."""
    items = list(items)
    results, errors = [], []
    if not items:
        return results, errors
    with ThreadPoolExecutor(max_workers=max(1, min(max_workers, len(items)))) as pool:
        futures = [(item, pool.submit(fn, item)) for item in items]
        for item, future in futures:
            try:
                results.append(future.result())
            except Exception as e:  # noqa: BLE001 - reported to the caller
                errors.append((item, e))
    return results, errors


def normalize_asn(asn):
    """60068, '60068', 'as60068' -> 'AS60068'."""
    digits = str(asn).strip().upper().removeprefix("AS")
    if not digits.isdigit():
        raise SyncError(f"config: invalid ASN '{asn}'")
    return f"AS{digits}"
# }}


# collecting prefixes {{
def fetch_asn_prefixes(session, asn, min_peers_seeing, timeout):
    """Fetches prefixes originated by one ASN from the RIPEstat API."""
    response = session.get(
        RIPE_ANNOUNCED_URL,
        params={
            "resource": asn,
            # RIPEstat defaults to 10, which drops low-visibility prefixes
            # (regional / selective announcements, typical for CDNs)
            "min_peers_seeing": min_peers_seeing,
            "sourceapp": RIPE_SOURCE_APP,
        },
        timeout=timeout,
    )
    response.raise_for_status()
    payload = response.json()
    if payload.get("status") != "ok":
        raise RuntimeError(f"RIPEstat status is '{payload.get('status')}'")
    prefixes = [item["prefix"] for item in payload["data"]["prefixes"]]
    if not prefixes:
        # an empty answer is far more likely a RIPEstat hiccup than reality,
        # and trusting it would delete every route of this ASN
        raise RuntimeError("RIPEstat returned no prefixes")
    return asn, prefixes


def resolve_hostname(hostname):
    """Resolves a hostname to a list of unique IPs (v4 and v6)."""
    ips = []
    try:
        for info in socket.getaddrinfo(hostname, None):
            ip = info[4][0].split('%', 1)[0]  # strip IPv6 scope id
            if ip not in ips:
                ips.append(ip)
    except socket.gaierror as e:
        log.warning("dns: cannot resolve %s: %s", hostname, e)
    return ips


def collect_raw(cfg):
    """Returns [(source, IPNetwork), ...] for every configured ASN and DNS name."""
    ripe = section(cfg, 'ripe')
    threads = int(ripe.get('threads', 5))
    timeout = ripe.get('timeout', 30)
    min_peers_seeing = int(ripe.get('min_peers_seeing', 0))
    asns = sorted({normalize_asn(asn) for asn in cfg.get('asns') or []})

    session = make_session(threads)
    results, errors = run_parallel(
        lambda asn: fetch_asn_prefixes(session, asn, min_peers_seeing, timeout), asns, threads)
    if errors:
        # a partial prefix list would make the sync DELETE the routes of
        # every ASN that failed to load - abort instead
        for asn, e in errors:
            log.error("ripe: error fetching prefixes for %s: %s", asn, e)
        raise SyncError("ripe: incomplete data, refusing to sync")

    raw = []
    for asn, prefixes in results:
        log.info("ripe: %s announces %d prefixes", asn, len(prefixes))
        raw.extend((asn, IPNetwork(prefix).cidr) for prefix in prefixes)
    for hostname in cfg.get('dns_names') or []:
        raw.extend((DNS_SOURCE, IPNetwork(ip)) for ip in resolve_hostname(hostname))

    if cfg.get('ipv4_only', False):
        raw = [(source, net) for source, net in raw if net.version == 4]
    return raw


def common_supernet(a, b):
    """
    Smallest CIDR containing both networks (same IP version).

    Deliberately not netaddr.spanning_cidr(): that one spans from the first
    address of the lower-sorted network to the last address of the
    higher-sorted one, so for nested input such as (10.0.0.0/21, 10.0.1.0/24)
    it returns 10.0.0.0/23 - SMALLER than its own argument.
    """
    first = min(a.first, b.first)
    last = max(a.last, b.last)
    width = 32 if a.version == 4 else 128
    prefixlen = width - (first ^ last).bit_length()
    return IPNetwork((first, prefixlen), version=a.version).cidr


def aggregate_lossy(networks, min_fill):
    """
    Folds neighbouring networks into their common supernet whenever that
    supernet would be filled by real prefixes to at least `min_fill` (0..1].
    This ADDS address space that was never announced, so only use it when
    routing a bit extra through the tunnel is acceptable.

    Single pass with a stack; every stack entry keeps fill >= min_fill, so an
    entry that turns out to be nested in a freshly built supernet is always
    absorbed and the result is guaranteed to be disjoint.
    """
    stack = []  # [(network, really_announced_addresses), ...]
    for net in cidr_merge(networks):
        real = net.size
        while stack and stack[-1][0].version == net.version:
            prev, prev_real = stack[-1]
            supernet = common_supernet(prev, net)
            if (prev_real + real) / supernet.size < min_fill:
                break
            stack.pop()
            net, real = supernet, prev_real + real
        stack.append((net, real))
    return [net for net, _ in stack]


def reduce_networks(networks, min_fill, excludes):
    """Exact merge -> optional lossy aggregation -> excludes. Returns a sorted, disjoint list."""
    merged = cidr_merge(networks)
    log.info("prefixes: %d raw -> %d after exact merge", len(networks), len(merged))

    if min_fill is not None:
        merged = aggregate_lossy(merged, min_fill)
        log.info("prefixes: %d after lossy aggregation (min_fill=%s)", len(merged), min_fill)

    if excludes:
        merged = (IPSet(merged) - excludes).iter_cidrs()
        log.info("prefixes: %d after excludes", len(merged))

    return sorted(merged)


def attribute_sources(final, raw):
    """
    Maps every final network to the sources whose prefixes overlap it.
    `final` is sorted and disjoint, and two CIDRs are either nested or
    disjoint, so for a raw prefix the candidates are: the final network
    containing its first address, plus any following final networks that
    start inside it (fragments left after excludes cut a hole in the prefix).
    """
    keys = [(net.version, net.first) for net in final]
    sources = [set() for _ in final]
    for source, net in raw:
        idx = bisect.bisect_right(keys, (net.version, net.first)) - 1
        if idx < 0 or final[idx].version != net.version or final[idx].last < net.first:
            idx += 1
        while idx < len(final) and final[idx].version == net.version and final[idx].first <= net.last:
            sources[idx].add(source)
            idx += 1
    return {str(net): sorted(found) for net, found in zip(final, sources)}


def build_desired(cfg):
    """Returns an ordered dict {prefix_str: [sources]} of networks that should be routed."""
    min_fill = section(cfg, 'aggregate').get('min_fill')
    if min_fill is not None:
        min_fill = float(min_fill)
        if not 0 < min_fill <= 1:
            raise SyncError("config: aggregate.min_fill must be within (0, 1]")

    raw = collect_raw(cfg)
    final = reduce_networks([net for _, net in raw], min_fill, IPSet(cfg.get('exclude') or []))
    if not final:
        raise SyncError("prefixes: nothing to route, refusing to sync an empty list")
    return attribute_sources(final, raw)
# }}


# netbird target {{
def sync_netbird(cfg, desired, dry_run):
    """Returns the number of failed API operations."""
    nb = section(cfg, 'netbird')
    route_cfg = section(cfg, 'route')
    require(nb, 'netbird', ['api_url', 'token', 'peer_id'])
    require(route_cfg, 'route', ['groups'])
    api_url = nb['api_url'].rstrip('/')
    threads = int(nb.get('threads', 20))

    session = make_session(threads, headers={
        "Authorization": f"Token {nb['token']}",
        "Content-Type": "application/json",
    })

    response = session.get(f"{api_url}/routes", timeout=NETBIRD_TIMEOUT)
    response.raise_for_status()
    # several routes may share one network (HA groups, leftovers of failed
    # runs), so keep all of them instead of a {network: route} dict
    existing = [
        (str(IPNetwork(route["network"]).cidr), route)
        for route in response.json() if route.get("network")
    ]
    existing_networks = {prefix for prefix, _ in existing}

    to_create = [prefix for prefix in desired if prefix not in existing_networks]
    to_delete = [
        (prefix, route) for prefix, route in existing
        if prefix not in desired and (route.get("description") or "").startswith(NETBIRD_MARKER)
    ]
    log.info("netbird: %d existing, %d to create, %d to delete", len(existing), len(to_create), len(to_delete))

    def create_route(prefix):
        log.info("netbird: creating route %s", prefix)
        if dry_run:
            return
        session.post(
            f"{api_url}/routes",
            json={
                "network": prefix,
                "peer": nb['peer_id'],
                "network_id": prefix.replace("/", "-")[:NETBIRD_NETWORK_ID_MAX_LENGTH],
                "enabled": True,
                "metric": route_cfg.get('metric', 9999),
                "groups": route_cfg['groups'],
                "description": f"{NETBIRD_MARKER} route to {prefix} for {','.join(desired[prefix]) or 'unknown'}",
                "masquerade": route_cfg.get('masquerade', True),
            },
            timeout=NETBIRD_TIMEOUT,
        ).raise_for_status()

    def delete_route(item):
        prefix, route = item
        log.info("netbird: deleting obsolete route %s (%s)", prefix, route['id'])
        if dry_run:
            return
        session.delete(f"{api_url}/routes/{route['id']}", timeout=NETBIRD_TIMEOUT).raise_for_status()

    _, create_errors = run_parallel(create_route, to_create, threads)
    for prefix, e in create_errors:
        log.error("netbird: error creating route %s: %s", prefix, e)

    _, delete_errors = run_parallel(delete_route, to_delete, threads)
    for (prefix, route), e in delete_errors:
        log.error("netbird: error deleting route %s (%s): %s", prefix, route['id'], e)

    return len(create_errors) + len(delete_errors)
# }}


# wireguard target {{
def read_route_file(path):
    """Reads CIDRs from the route file, skipping blanks and '#' comments."""
    networks = set()
    if not os.path.isfile(path):
        return networks
    with open(path, 'r') as fh:
        for line in fh:
            line = line.split('#', 1)[0].strip()
            if line:
                networks.add(str(IPNetwork(line).cidr))
    return networks


def write_route_file(path, networks):
    """Atomically rewrites the route file."""
    tmp_path = path + '.tmp'
    with open(tmp_path, 'w') as fh:
        fh.write(WG_FILE_HEADER + "\n")
        fh.writelines(network + "\n" for network in networks)
    os.replace(tmp_path, path)


def read_kernel_routes(interface):
    """
    Returns the set of CIDRs currently routed via `interface` (main table),
    or None when the interface is missing / down.
    """
    routes = set()
    for family in ("inet", "inet6"):
        result = subprocess.run(
            ["ip", "--json", "--family", family, "route", "show", "dev", interface],
            capture_output=True, text=True)
        if result.returncode != 0:
            log.warning("wireguard: cannot list routes on %s: %s", interface, result.stderr.strip())
            return None
        for entry in json.loads(result.stdout or "[]"):
            dst = entry.get("dst")
            if dst and dst != "default":
                routes.add(str(IPNetwork(dst).cidr))
    return routes


def apply_kernel_routes(interface, to_delete, to_add, dry_run):
    """Applies all changes with a single `ip --batch` call. Returns True on success."""
    commands = [f"route del {prefix} dev {interface}" for prefix in to_delete]
    commands += [f"route replace {prefix} dev {interface}" for prefix in to_add]
    for command in commands:
        log.info("wireguard: ip %s", command)
    if dry_run or not commands:
        return True
    # --force: keep going after a failed line, failures are reported on stderr
    result = subprocess.run(
        ["ip", "--force", "--batch", "-"],
        input="\n".join(commands) + "\n", capture_output=True, text=True)
    if result.returncode != 0:
        log.error("wireguard: some route changes failed:\n%s", result.stderr.strip())
    return result.returncode == 0


def sync_wireguard(cfg, desired, dry_run):
    """
    The file is the record of what this script manages; the kernel routing
    table is the record of what is actually applied. Additions are diffed
    against the kernel, so routes lost on an interface restart or after a
    failed `ip route` come back on the next run. Deletions are limited to
    prefixes from the file, so foreign routes on the interface are never touched.

    Returns the number of failed operations.
    """
    wg = section(cfg, 'wireguard')
    path = wg.get('file', '/etc/wireguard/via-amsnl1.txt')
    interface = wg.get('interface', 'wg0')
    apply_routes = wg.get('apply_routes', True)

    managed = read_route_file(path)
    wanted = set(desired)
    failures = 0

    if apply_routes:
        kernel = read_kernel_routes(interface)
        if kernel is None:
            log.warning("wireguard: %s is unavailable, updating the route file only", interface)
        else:
            to_delete = sorted((managed - wanted) & kernel, key=IPNetwork)
            to_add = sorted(wanted - kernel, key=IPNetwork)
            log.info("wireguard: %d routes on %s, %d to add, %d to delete",
                     len(kernel), interface, len(to_add), len(to_delete))
            if not apply_kernel_routes(interface, to_delete, to_add, dry_run):
                failures += 1

    if managed != wanted:
        log.info("wireguard: %s: %d -> %d networks (+%d, -%d)",
                 path, len(managed), len(wanted), len(wanted - managed), len(managed - wanted))
        if not dry_run:
            write_route_file(path, sorted(wanted, key=IPNetwork))
    else:
        log.info("wireguard: %s is up to date (%d networks)", path, len(managed))
    return failures
# }}


def main():
    parser = argparse.ArgumentParser(description="Sync RIPE-announced networks into NetBird or a WireGuard route file")
    parser.add_argument("--config", help="path to YAML config (default: ~/.<script>.yaml, ./.config.yaml, <script dir>/.config.yaml)")
    parser.add_argument("--target", choices=["netbird", "wireguard"], help="sync target (overrides `target:` from config)")
    parser.add_argument("--dry-run", action="store_true", help="only print what would be changed")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s", stream=sys.stderr)

    try:
        cfg = load_config(args.config)
        target = args.target or cfg.get('target')
        if target not in ("netbird", "wireguard"):
            raise SyncError("target must be 'netbird' or 'wireguard' (use --target or `target:` in config)")

        desired = build_desired(cfg)
        log.info("prefixes: %d networks to route", len(desired))

        if target == "netbird":
            failures = sync_netbird(cfg, desired, args.dry_run)
        else:
            failures = sync_wireguard(cfg, desired, args.dry_run)
    except (SyncError, requests.RequestException) as e:
        log.error("%s", e)
        return 1
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
