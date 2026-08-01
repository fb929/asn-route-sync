#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import requests
import json
import os
from os.path import expanduser
import sys
import yaml
import threading
import queue
from netaddr import cidr_merge

# load config {{
scriptName = os.path.basename(sys.argv[0]).split('.')[0]
scriptDir = os.path.dirname(os.path.abspath(__file__))
homeDir = expanduser("~")
defaultConfigFiles = [
    homeDir + '/.' + scriptName + '.yaml',
    os.path.join(os.getcwd(), '.config.yaml'),
    os.path.join(scriptDir, '.config.yaml'),
]
for configFile in defaultConfigFiles:
    if os.path.isfile(configFile):
        try:
            with open(configFile, 'r') as ymlfile:
                try:
                    cfg = yaml.load(ymlfile, Loader=yaml.Loader)
                except Exception as e:
                    print("main: skipping load config file: '%s', error '%s'", configFile, e)
                    continue
        except:
            continue
# }}

# number of worker threads for RIPE stat API requests
# configurable via: ripe: { threads: 10 }, defaults to 5
RIPE_THREADS = cfg.get('ripe', {}).get('threads', 1)

# number of worker threads for NetBird API requests
# configurable via: netbird: { threads: 10 }, defaults to 5
NETBIRD_THREADS = cfg.get('netbird', {}).get('threads', 20)


def run_workers(worker_fn, items, num_workers):
    """
    Plain worker-pool implementation: spins up `num_workers` threads that
    pull items off a shared queue and call worker_fn(item) until the queue
    is empty. Returns (results, errors) as lists collected under a lock.
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


# create session
session = requests.Session()
session.headers.update({
    "Authorization": f"Token {cfg['netbird']['token']}",
    "Content-Type": "application/json",
})
# bump the connection pool so it can actually serve NETBIRD_THREADS
# concurrent requests instead of queuing them behind the default pool size (10)
adapter = requests.adapters.HTTPAdapter(pool_connections=NETBIRD_THREADS, pool_maxsize=NETBIRD_THREADS)
session.mount("http://", adapter)
session.mount("https://", adapter)

# get exists routes
routes = session.get(f"{cfg['netbird']['api_url']}/routes").json()
existing = {}
for route in routes:
    existing[route["network"]] = route
# debug
#print(f"existing routes: {existing}")


def fetch_asn_prefixes(asn):
    """Fetches the list of announced prefixes for a single ASN from the RIPE stat API."""
    r = requests.get(
        "https://stat.ripe.net/data/announced-prefixes/data.json",
        params={"resource": asn},
        timeout=30,
    )
    r.raise_for_status()
    prefixes = [p["prefix"] for p in r.json()["data"]["prefixes"]]
    return asn, prefixes


# fetch prefixes for all ASNs from RIPE, in parallel
fetch_results, fetch_errors = run_workers(fetch_asn_prefixes, cfg['asns'], RIPE_THREADS)
for asn, e in fetch_errors:
    print(f"error fetching prefixes for asn {asn}: {e}")

asn_to_prefixes = {asn: prefixes for asn, prefixes in fetch_results}

# aggregate prefixes per ASN into the minimal set of covering CIDRs.
# IPSet only merges exact sibling blocks into their parent, so this never
# pulls in address space that wasn't part of the original prefixes -
# it just reduces the number of routes when adjacent /24s (etc.) can be
# folded into a single larger block.
asn_to_merged = {}
ripe_prefixes = []
to_create = []
for asn, prefixes in asn_to_prefixes.items():
    merged_prefixes = cidr_merge(prefixes)
    if len(merged_prefixes) < len(prefixes):
        print(f"asn {asn}: merged {len(prefixes)} prefixes into {len(merged_prefixes)} routes")
    asn_to_merged[asn] = [str(net) for net in merged_prefixes]
    for prefix in merged_prefixes:
        prefix = str(prefix)
        if prefix not in ripe_prefixes:
            ripe_prefixes.append(prefix)
        if prefix not in existing and (asn, prefix) not in to_create:
            to_create.append((asn, prefix))


def create_route(item):
    """Creates a single NetBird route for one (asn, prefix) pair."""
    asn, prefix = item
    print(f"creating route for: {prefix}")
    response = session.post(
        f"{cfg['netbird']['api_url']}/routes",
        json={
            "network": prefix,
            "peer": cfg['netbird']['peer_id'],
            "network_id": prefix.replace("/", "-"),
            "enabled": True,
            "metric": cfg['route']['metric'],
            "groups": cfg['route']['groups'],
            "description": f"Managed by RIPE sync: route to {prefix} for asn {asn}",
            "masquerade": cfg['route']['masquerade'],
        },
    )
    response.raise_for_status()
    return prefix, response.text, response.status_code


print(f"Number of ripe_prefixes: {len(ripe_prefixes)}")
print(f"Number of routes to create: {len(to_create)}")
create_results, create_errors = run_workers(create_route, to_create, NETBIRD_THREADS)
for prefix, text, status_code in create_results:
    if status_code == 200 and text.strip() in ("", "{}"):
        continue
    print(text, status_code)
for (asn, prefix), e in create_errors:
    print(f"error creating route for {prefix}: {e}")


def delete_route(item):
    """Deletes a single obsolete NetBird route."""
    prefix, route = item
    print(f"Deleting obsolete route {prefix} ({route['id']})")
    response = session.delete(f"{cfg['netbird']['api_url']}/routes/{route['id']}")
    response.raise_for_status()
    return prefix, response.text, response.status_code

to_delete = []
for prefix, route in existing.items():
    if route.get("description", "").startswith("Managed by RIPE sync:") and prefix not in ripe_prefixes:
        to_delete.append((prefix, route))

print(f"Number of Routes to delete: {len(to_delete)}")
delete_results, delete_errors = run_workers(delete_route, to_delete, NETBIRD_THREADS)
for prefix, text, status_code in delete_results:
    if status_code == 200 and text.strip() in ("", "{}"):
        continue
    print(text, status_code)
for (prefix, route), e in delete_errors:
    print(f"error deleting route for {prefix}: {e}")
