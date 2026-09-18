# ASN Route Sync

Synchronizes NetBird, WireGuard routes with prefixes announced by selected ASNs from RIPE.

The script:

* Downloads announced prefixes from RIPE Stat API
* Removes existing NetBird, WireGuard routes before recreating them
* Creates routes with a configurable peer, metric, groups, and masquerading settings
* Uses a YAML configuration file

## Requirements

* Python 3.9+
* NetBird Management API access token
* A routing peer configured in NetBird

## Installation

Install dependencies:

```bash
pip install requests pyyaml
```

Clone the repository:

```bash
git clone https://github.com/fb929/netbird-ripe-sync.git
cd netbird-ripe-sync
```

## Configuration

Create a `.config.yaml` file:

```yaml
netbird:
  api_url: "https://netbird.example.com/api"
  token: "YOUR_NETBIRD_TOKEN"
  peer_id: "YOUR_ROUTING_PEER_ID"

route:
  metric: 9999
  masquerade: true
  groups:
    - "d8cat8ako0rs739ir2kg"

asns:
  - "AS15169"
  - "AS62041"
  - "AS59930"
```

### Configuration Parameters

#### netbird.api_url

NetBird Management API URL.

Example:

```yaml
api_url: "https://netbird.example.com/api"
```

#### netbird.token

NetBird API token with permissions to manage routes.

#### netbird.peer_id

Routing peer that will advertise the routes.

#### route.metric

Route metric.

Example:

```yaml
metric: 9999
```

#### route.masquerade

Enable source NAT (masquerading) on the routing peer.

Example:

```yaml
masquerade: true
```

#### route.groups

Distribution groups that should receive the routes.

Example:

```yaml
groups:
  - "d8cat8ako0rs739ir2kg"
```

#### asns

List of ASNs to synchronize.

Example:

```yaml
asns:
  - "AS62041"
  - "AS59930"
```

## Usage

Run the script:

```bash
python sync-ripe-routes.py
```

## How It Works

1. Fetch existing routes from NetBird.
2. Fetch announced prefixes for configured ASNs from RIPE.
3. Delete matching existing routes.
4. Recreate routes using the latest RIPE data.

## License

MIT
