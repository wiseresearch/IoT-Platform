#!/usr/bin/env python3

"""
Suricata quarantine utility for the Unified Security Platform.

Supports:
1) Manual mode:
   - quarantine <ip> [reason]
   - unquarantine <ip>
   - list
2) Monitor mode:
   - monitor
   Reads EVE alerts and auto-quarantines sources when suspicious SID thresholds are hit.
"""

import ipaddress
import json
import logging
import os
import shutil
import subprocess
import sys
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def env_int(name, default):
    try:
        return int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default


def parse_sid_set(value):
    if not value:
        return set()
    parsed = set()
    for item in str(value).split(","):
        token = item.strip()
        if token.isdigit():
            parsed.add(int(token))
    return parsed


class QuarantineManager:
    def __init__(self):
        self.quarantine_log = os.getenv("SURICATA_QUARANTINE_LOG", "/var/log/suricata/quarantine.log")
        self.eve_file = os.getenv("SURICATA_EVE_FILE", "/var/log/suricata/eve.json")
        self.threshold_count = env_int("SURICATA_THRESHOLD_COUNT", 10)
        self.threshold_seconds = env_int("SURICATA_THRESHOLD_SECONDS", 30)
        self.history_window_seconds = env_int("SURICATA_HISTORY_WINDOW_SECONDS", 900)
        self.repeat_min_distinct_sids = env_int("SURICATA_REPEAT_MIN_DISTINCT_SIDS", 3)
        self.repeat_min_alerts = env_int("SURICATA_REPEAT_MIN_ALERTS", 12)
        self.timeout_seconds = env_int("SURICATA_QUARANTINE_TIMEOUT_SECONDS", 3600)
        # Empty set means "all alert SIDs are eligible"
        self.suspect_sids = parse_sid_set(os.getenv("SURICATA_SUSPECT_SIDS", ""))

        self.nft_family = os.getenv("SURICATA_NFT_FAMILY", "inet")
        self.nft_table = os.getenv("SURICATA_NFT_TABLE", "filter")
        self.nft_set = os.getenv("SURICATA_NFT_SET", "quarantine")
        self.backend = os.getenv("SURICATA_QUARANTINE_BACKEND", "auto").lower()

        self.history = defaultdict(list)
        self.sid_history = defaultdict(list)
        self.quarantined_cache = {}

    def _run(self, cmd):
        return subprocess.run(cmd, capture_output=True, text=True, check=False)

    def _command_exists(self, name):
        return shutil.which(name) is not None

    def _is_valid_ip(self, ip_address):
        try:
            ipaddress.ip_address(ip_address)
            return True
        except ValueError:
            return False

    def _write_log(self, action, ip_address, reason, details=None):
        os.makedirs(os.path.dirname(self.quarantine_log), exist_ok=True)
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "ip": ip_address,
            "reason": reason,
            "backend": self.backend,
        }
        if isinstance(details, dict) and details:
            entry["details"] = details
        with open(self.quarantine_log, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")

    def _list_nft_set(self):
        return self._run(["nft", "list", "set", self.nft_family, self.nft_table, self.nft_set])

    def _nft_contains_ip(self, ip_address):
        if not self._command_exists("nft"):
            return False
        result = self._list_nft_set()
        return result.returncode == 0 and ip_address in (result.stdout or "")

    def _add_nft(self, ip_address):
        if not self._command_exists("nft"):
            return False, "nft not available"
        if self._nft_contains_ip(ip_address):
            return True, "already in nft set"
        element = f"{{ {ip_address} timeout {self.timeout_seconds}s }}"
        cmd = [
            "nft", "add", "element", self.nft_family, self.nft_table, self.nft_set,
            element
        ]
        result = self._run(cmd)
        if result.returncode == 0:
            return True, "added to nft set"
        stderr = (result.stderr or "").strip()
        return False, f"nft add failed: {stderr}"

    def _remove_nft(self, ip_address):
        if not self._command_exists("nft"):
            return False, "nft not available"
        element = f"{{ {ip_address} }}"
        cmd = ["nft", "delete", "element", self.nft_family, self.nft_table, self.nft_set, element]
        result = self._run(cmd)
        if result.returncode == 0:
            return True, "removed from nft set"
        stderr = (result.stderr or "").strip()
        return False, f"nft remove failed: {stderr}"

    def _iptables_has_rule(self, chain, ip_address):
        result = self._run(["iptables", "-C", chain, "-s", ip_address, "-j", "DROP"])
        return result.returncode == 0

    def _add_iptables(self, ip_address):
        if not self._command_exists("iptables"):
            return False, "iptables not available"
        for chain in ("INPUT", "FORWARD"):
            if not self._iptables_has_rule(chain, ip_address):
                result = self._run(["iptables", "-I", chain, "1", "-s", ip_address, "-j", "DROP"])
                if result.returncode != 0:
                    stderr = (result.stderr or "").strip()
                    return False, f"iptables add failed on {chain}: {stderr}"
        return True, "added to iptables"

    def _remove_iptables(self, ip_address):
        if not self._command_exists("iptables"):
            return False, "iptables not available"
        for chain in ("INPUT", "FORWARD"):
            self._run(["iptables", "-D", chain, "-s", ip_address, "-j", "DROP"])
        return True, "removed from iptables"

    def _active_backend(self):
        if self.backend == "nft":
            return "nft"
        if self.backend == "iptables":
            return "iptables"
        if self.backend == "auto":
            if self._command_exists("nft") and self._list_nft_set().returncode == 0:
                return "nft"
            return "iptables"
        return "iptables"

    def _is_already_quarantined(self, ip_address):
        now = datetime.now(timezone.utc)
        cached = self.quarantined_cache.get(ip_address)
        if cached and (now - cached).total_seconds() < self.timeout_seconds:
            return True

        backend = self._active_backend()
        if backend == "nft":
            exists = self._nft_contains_ip(ip_address)
        else:
            exists = self._iptables_has_rule("INPUT", ip_address) or self._iptables_has_rule("FORWARD", ip_address)
        if exists:
            self.quarantined_cache[ip_address] = now
        return exists

    def quarantine_ip(self, ip_address, reason="Security threat detected", details=None):
        if not self._is_valid_ip(ip_address):
            return False, "Invalid IP address"
        if self._is_already_quarantined(ip_address):
            backend = self._active_backend()
            log_details = dict(details or {})
            log_details["backend_used"] = backend
            log_details["apply_result"] = "already quarantined"
            self._write_log("quarantine", ip_address, reason, details=log_details)
            logger.info(f"Quarantine event recorded for {ip_address}: already quarantined")
            return True, "Already quarantined"

        backend = self._active_backend()
        if backend == "nft":
            ok, message = self._add_nft(ip_address)
        else:
            ok, message = self._add_iptables(ip_address)

        if ok:
            self.quarantined_cache[ip_address] = datetime.now(timezone.utc)
            log_details = dict(details or {})
            log_details["backend_used"] = backend
            log_details["apply_result"] = message
            self._write_log("quarantine", ip_address, reason, details=log_details)
            logger.info(f"Quarantined {ip_address}: {reason} ({message})")
            return True, message
        logger.error(f"Failed to quarantine {ip_address}: {message}")
        return False, message

    def unquarantine_ip(self, ip_address):
        if not self._is_valid_ip(ip_address):
            return False, "Invalid IP address"

        backend = self._active_backend()
        if backend == "nft":
            ok, message = self._remove_nft(ip_address)
        else:
            ok, message = self._remove_iptables(ip_address)

        self.quarantined_cache.pop(ip_address, None)
        self._write_log("unquarantine", ip_address, "Manual unquarantine")
        if ok:
            logger.info(f"Unquarantined {ip_address}: {message}")
            return True, message
        logger.warning(f"Unquarantine warning for {ip_address}: {message}")
        return False, message

    def list_quarantined(self):
        now = datetime.now(timezone.utc)
        for ip, seen in list(self.quarantined_cache.items()):
            if (now - seen).total_seconds() > self.timeout_seconds:
                self.quarantined_cache.pop(ip, None)
        return sorted(self.quarantined_cache.keys())

    def process_alert_event(self, event):
        if event.get("event_type") != "alert":
            return None

        alert = event.get("alert") or {}
        sid = alert.get("signature_id")
        if sid is None:
            return None

        try:
            sid = int(sid)
        except (TypeError, ValueError):
            return None

        if self.suspect_sids and sid not in self.suspect_sids:
            return None

        src_ip = event.get("src_ip")
        if not src_ip or not self._is_valid_ip(src_ip):
            return None

        now = datetime.now(timezone.utc)

        # Short burst tracking (classic threshold in a small window)
        window_start = now - timedelta(seconds=self.threshold_seconds)
        self.history[src_ip].append(now)
        self.history[src_ip] = [ts for ts in self.history[src_ip] if ts >= window_start]
        burst_count = len(self.history[src_ip])

        # Longer historical tracking per IP across multiple Suricata rules (SIDs)
        history_window_start = now - timedelta(seconds=self.history_window_seconds)
        self.sid_history[src_ip].append((now, sid))
        self.sid_history[src_ip] = [
            (ts, sid_value) for ts, sid_value in self.sid_history[src_ip] if ts >= history_window_start
        ]
        long_count = len(self.sid_history[src_ip])
        distinct_sids = len({sid_value for _, sid_value in self.sid_history[src_ip]})

        reason = None
        reason_type = None
        if burst_count >= self.threshold_count:
            reason_type = "burst-threshold"
            reason = f"Suricata threshold reached ({burst_count} alerts in {self.threshold_seconds}s)"
        elif long_count >= self.repeat_min_alerts and distinct_sids >= self.repeat_min_distinct_sids:
            reason_type = "repeat-offender"
            reason = (
                f"Repeat offender: {long_count} alerts from {distinct_sids} distinct rules "
                f"in {self.history_window_seconds}s"
            )

        if reason:
            decision_details = {
                "reason_type": reason_type,
                "trigger_sid": sid,
                "burst_count": burst_count,
                "history_count": long_count,
                "distinct_sids": distinct_sids,
                "recent_sids": sorted({sid_value for _, sid_value in self.sid_history[src_ip]}),
                "short_threshold_count": self.threshold_count,
                "short_threshold_seconds": self.threshold_seconds,
                "history_window_seconds": self.history_window_seconds,
                "repeat_min_alerts": self.repeat_min_alerts,
                "repeat_min_distinct_sids": self.repeat_min_distinct_sids,
            }
            ok, message = self.quarantine_ip(src_ip, reason=reason, details=decision_details)
            self.history[src_ip].clear()
            self.sid_history[src_ip].clear()
            return {
                "ip": src_ip,
                "quarantined": ok,
                "message": message,
                "sid": sid,
                "count": burst_count,
                "history_count": long_count,
                "distinct_sids": distinct_sids,
                "reason_type": reason_type,
            }
        return None

    def monitor(self):
        if not os.path.exists(self.eve_file):
            raise FileNotFoundError(f"EVE file not found: {self.eve_file}")

        logger.info(
            "Starting Suricata monitor. file=%s threshold=%s/%ss repeat=%s alerts/%s sids in %ss sids=%s backend=%s",
            self.eve_file, self.threshold_count, self.threshold_seconds,
            self.repeat_min_alerts, self.repeat_min_distinct_sids, self.history_window_seconds,
            sorted(self.suspect_sids) if self.suspect_sids else "all-alert-sids",
            self._active_backend()
        )
        with open(self.eve_file, "r", encoding="utf-8", errors="ignore") as f:
            f.seek(0, os.SEEK_END)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.2)
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                result = self.process_alert_event(event)
                if result:
                    logger.warning(
                        "Auto-quarantine decision: ip=%s sid=%s burst_count=%s history_count=%s distinct_sids=%s reason_type=%s result=%s",
                        result["ip"],
                        result["sid"],
                        result["count"],
                        result.get("history_count"),
                        result.get("distinct_sids"),
                        result.get("reason_type"),
                        result["message"],
                    )


def print_usage():
    print("Usage:")
    print("  python3 suricata_quarantine.py monitor")
    print("  python3 suricata_quarantine.py quarantine <ip> [reason]")
    print("  python3 suricata_quarantine.py unquarantine <ip>")
    print("  python3 suricata_quarantine.py list")


def main():
    if len(sys.argv) < 2:
        print_usage()
        sys.exit(1)

    action = sys.argv[1].lower().strip()
    manager = QuarantineManager()

    if action == "monitor":
        try:
            manager.monitor()
        except KeyboardInterrupt:
            logger.info("Monitor stopped by user")
        except Exception as e:
            logger.error(f"Monitor failed: {str(e)}")
            sys.exit(1)
        return

    if action == "list":
        items = manager.list_quarantined()
        if not items:
            print("No IPs currently quarantined")
        else:
            print("Quarantined IPs:")
            for ip_address in items:
                print(f"  - {ip_address}")
        return

    if action in {"quarantine", "unquarantine"} and len(sys.argv) < 3:
        print_usage()
        sys.exit(1)

    ip_address = sys.argv[2] if len(sys.argv) >= 3 else None
    reason = sys.argv[3] if len(sys.argv) >= 4 else "Manual action"

    if action == "quarantine":
        ok, message = manager.quarantine_ip(ip_address, reason=reason)
        print(f"{'OK' if ok else 'ERROR'}: {message}")
        sys.exit(0 if ok else 1)

    if action == "unquarantine":
        ok, message = manager.unquarantine_ip(ip_address)
        print(f"{'OK' if ok else 'ERROR'}: {message}")
        sys.exit(0 if ok else 1)

    print_usage()
    sys.exit(1)


if __name__ == "__main__":
    main()
