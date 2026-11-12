import ipaddress
import json
import os
import re
import subprocess


def load_local_env(env_path=None):
    """Load simple KEY=VALUE pairs from the repo .env for host-side scripts."""
    if env_path is None:
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        env_path = os.path.join(repo_root, ".env")

    if not os.path.exists(env_path):
        return

    try:
        with open(env_path, "r", encoding="utf-8") as handle:
            for raw_line in handle:
                line = raw_line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue

                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip()

                if not key or key in os.environ:
                    continue

                if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
                    value = value[1:-1]

                os.environ[key] = value
    except OSError:
        return


def _run_command(args, timeout=5):
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    except Exception:
        return ""

    return result.stdout or ""


def list_connected_interfaces():
    if os.name != "nt":
        try:
            links = json.loads(_run_command(["ip", "-j", "link", "show"]) or "[]")
        except json.JSONDecodeError:
            return []
        return [
            link.get("ifname")
            for link in links
            if link.get("ifname") and link.get("operstate") == "UP"
        ]

    output = _run_command(["netsh", "interface", "show", "interface"])
    names = []

    for line in output.splitlines():
        stripped = line.strip()
        if not stripped or stripped.lower().startswith("admin state"):
            continue
        if stripped and set(stripped) == {"-"}:
            continue

        parts = re.split(r"\s{2,}", stripped)
        if len(parts) >= 4 and parts[1].lower() == "connected":
            names.append(parts[3])

    return names


def list_ipv4_interfaces():
    if os.name != "nt":
        try:
            addresses = json.loads(_run_command(["ip", "-j", "-4", "addr", "show"]) or "[]")
            routes = json.loads(_run_command(["ip", "-j", "-4", "route", "show", "default"]) or "[]")
        except json.JSONDecodeError:
            return []

        default_gateways = {}
        for route in routes:
            dev = route.get("dev")
            if dev and route.get("gateway") and dev not in default_gateways:
                default_gateways[dev] = route.get("gateway")

        interfaces = []
        for link in addresses:
            name = link.get("ifname")
            if not name or name == "lo":
                continue
            for addr in link.get("addr_info", []):
                if addr.get("family") != "inet" or not addr.get("local"):
                    continue
                prefix = addr.get("prefixlen")
                subnet = None
                if prefix is not None:
                    try:
                        subnet = str(ipaddress.ip_network(f"{addr['local']}/{prefix}", strict=False))
                    except ValueError:
                        subnet = None
                interfaces.append({
                    "name": name,
                    "ip": addr.get("local"),
                    "subnet": subnet,
                    "gateway": default_gateways.get(name),
                    "mac": link.get("address"),
                })
        return interfaces

    output = _run_command(["netsh", "interface", "ipv4", "show", "addresses"])
    interfaces = []
    current = None

    for line in output.splitlines():
        stripped = line.strip()
        header_match = re.match(r'^Configuration for interface "(.+)"$', stripped)
        if header_match:
            if current:
                interfaces.append(current)
            current = {
                "name": header_match.group(1),
                "ip": None,
                "subnet": None,
                "gateway": None,
            }
            continue

        if not current:
            continue

        ip_match = re.match(r"^IP Address:\s+(\d+\.\d+\.\d+\.\d+)$", stripped)
        if ip_match:
            current["ip"] = ip_match.group(1)
            continue

        subnet_match = re.match(r"^Subnet Prefix:\s+(\d+\.\d+\.\d+\.\d+/\d+)", stripped)
        if subnet_match:
            current["subnet"] = subnet_match.group(1)
            continue

        gateway_match = re.match(r"^Default Gateway:\s+(\d+\.\d+\.\d+\.\d+)$", stripped)
        if gateway_match:
            current["gateway"] = gateway_match.group(1)

    if current:
        interfaces.append(current)

    return interfaces


def detect_primary_interface(preferred_interface=None):
    preferred = preferred_interface or os.getenv("TSHARK_INTERFACE") or os.getenv("SCAN_INTERFACE")
    fallback_subnet = os.getenv("FALLBACK_SUBNET", "192.168.1.0/24")
    connected_names = set(list_connected_interfaces())
    candidates = []

    for interface in list_ipv4_interfaces():
        ip_value = interface.get("ip")
        if not ip_value:
            continue

        try:
            ip_obj = ipaddress.ip_address(ip_value)
        except ValueError:
            continue

        if ip_obj.is_loopback or ip_obj.is_link_local:
            continue

        score = 0
        if preferred and interface["name"] == preferred:
            score += 100
        if interface["name"] in connected_names:
            score += 50
        if interface.get("gateway"):
            score += 25
        if ip_obj.is_private:
            score += 10

        candidates.append((score, interface))

    if candidates:
        candidates.sort(key=lambda item: item[0], reverse=True)
        return candidates[0][1]

    return {
        "name": preferred or "Wi-Fi 2",
        "ip": None,
        "subnet": fallback_subnet,
        "gateway": None,
    }


def detect_primary_subnet(preferred_interface=None, fallback_subnet=None):
    network_info = detect_primary_interface(preferred_interface=preferred_interface)
    subnet = network_info.get("subnet")
    if subnet:
        return subnet

    return fallback_subnet or os.getenv("FALLBACK_SUBNET", "192.168.1.0/24")
