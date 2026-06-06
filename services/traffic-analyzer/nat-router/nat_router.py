#!/usr/bin/env python3

"""
NAT Router + Suricata Rule Management for Unified Security Platform.
Provides:
- Basic NAT/routing lifecycle
- Suricata rule listing/add/remove by SID
- Suricata reload endpoint for runtime updates
"""

import os
import subprocess
import logging
import time
import re
import shutil
import json
from flask import Flask, jsonify, request

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)


class NATRouter:
    def __init__(self):
        self.running = False
        self.rules_path = os.getenv("SURICATA_RULES_PATH", "/etc/suricata/suricata.rules")
        self.suricata_process_name = os.getenv("SURICATA_PROCESS_NAME", "suricata")
        self.eve_path = os.getenv("SURICATA_EVE_FILE", "/var/log/suricata/eve.json")
        self.suricatasc_path = os.getenv("SURICATASC_PATH", "suricatasc")
        self.quarantine_log_path = os.getenv("SURICATA_QUARANTINE_LOG", "/var/log/suricata/quarantine.log")

    def _run(self, cmd, check=False):
        return subprocess.run(cmd, capture_output=True, text=True, check=check)

    def setup_nat_rules(self):
        """Setup basic NAT and routing rules"""
        try:
            # Enable IP forwarding
            self._run(['sysctl', 'net.ipv4.ip_forward=1'], check=False)

            # Setup basic iptables rules for NAT
            check_rule = self._run(
                ['iptables', '-t', 'nat', '-C', 'POSTROUTING', '-s', '172.20.0.0/24', '-o', 'eth1', '-j', 'MASQUERADE'],
                check=False
            )
            if check_rule.returncode != 0:
                self._run(
                    ['iptables', '-t', 'nat', '-A', 'POSTROUTING', '-s', '172.20.0.0/24', '-o', 'eth1', '-j', 'MASQUERADE'],
                    check=False
                )

            logger.info("NAT rules configured successfully")
        except Exception as e:
            logger.error(f"Error setting up NAT: {e}")

    def start_routing(self):
        """Start the routing service"""
        if not self.running:
            self.running = True
            self.setup_nat_rules()
            logger.info("NAT Router started")
    
    def stop_routing(self):
        """Stop the routing service"""
        if self.running:
            self.running = False
            logger.info("NAT Router stopped")

    def _ensure_rules_file(self):
        rules_dir = os.path.dirname(self.rules_path)
        if rules_dir:
            os.makedirs(rules_dir, exist_ok=True)
        if not os.path.exists(self.rules_path):
            with open(self.rules_path, 'w', encoding='utf-8') as f:
                f.write("")

    def list_rules(self):
        self._ensure_rules_file()
        with open(self.rules_path, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]

    def add_rule(self, rule_text):
        rule = (rule_text or "").strip()
        if not rule:
            raise ValueError("Rule text is required.")
        if "sid:" not in rule:
            raise ValueError("Rule must include a sid.")

        self._ensure_rules_file()
        existing = self.list_rules()
        if rule in existing:
            return {"added": False, "message": "Rule already exists."}

        with open(self.rules_path, 'ab+') as f:
            f.seek(0, os.SEEK_END)
            if f.tell() > 0:
                f.seek(-1, os.SEEK_END)
                last_byte = f.read(1)
                if last_byte != b'\n':
                    f.write(b'\n')
            f.write(rule.encode('utf-8') + b'\n')
        return {"added": True, "message": "Rule added."}

    def remove_rule_by_sid(self, sid):
        sid_text = str(sid or "").strip()
        if not sid_text.isdigit():
            raise ValueError("SID must be a numeric value.")

        self._ensure_rules_file()
        pattern = re.compile(rf"sid\s*:\s*{re.escape(sid_text)}\s*;")
        with open(self.rules_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        kept = [line for line in lines if not pattern.search(line)]
        removed = len(lines) - len(kept)
        if removed == 0:
            return {"removed": 0, "message": f"No rule found for SID {sid_text}."}

        with open(self.rules_path, 'w', encoding='utf-8') as f:
            f.writelines(kept)
        return {"removed": removed, "message": f"Removed {removed} rule(s) for SID {sid_text}."}

    def _find_suricata_pid(self):
        attempts = [
            ['pgrep', '-o', self.suricata_process_name],
            ['pgrep', '-o', '-f', self.suricata_process_name],
        ]

        for cmd in attempts:
            result = self._run(cmd, check=False)
            if result.returncode != 0:
                continue

            output = (result.stdout or "").strip().splitlines()
            if not output:
                continue

            pid_text = output[0].strip()
            if pid_text.isdigit():
                return pid_text

        return None

    def reload_suricata(self):
        """
        Try the command socket first, then fall back to signaling the
        actual Suricata master process. Never signal PID 1 here because
        PID 1 is the NAT router API, not Suricata.
        """
        errors = []

        suricatasc_binary = shutil.which(self.suricatasc_path)
        if suricatasc_binary:
            cmd = [suricatasc_binary, '-c', 'reload-rules']
            result = self._run(cmd, check=False)
            if result.returncode == 0:
                return {
                    "reloaded": True,
                    "method": " ".join(cmd),
                    "stdout": (result.stdout or "").strip()
                }
            errors.append({
                "command": " ".join(cmd),
                "stdout": (result.stdout or "").strip(),
                "error": (result.stderr or "").strip()
            })

        pid = self._find_suricata_pid()
        if pid:
            cmd = ['kill', '-USR2', pid]
            result = self._run(cmd, check=False)
            if result.returncode == 0:
                return {"reloaded": True, "method": " ".join(cmd)}
            errors.append({
                "command": " ".join(cmd),
                "error": (result.stderr or "").strip()
            })

        fallback_cmd = ['pkill', '-USR2', self.suricata_process_name]
        result = self._run(fallback_cmd, check=False)
        if result.returncode == 0:
            return {"reloaded": True, "method": " ".join(fallback_cmd)}
        errors.append({
            "command": " ".join(fallback_cmd),
            "error": (result.stderr or "").strip()
        })

        return {"reloaded": False, "errors": errors}

    def suricata_status(self):
        result = self._run(['pgrep', '-af', self.suricata_process_name], check=False)
        running = result.returncode == 0
        processes = [line.strip() for line in (result.stdout or "").splitlines() if line.strip()]
        return {
            "running": running,
            "processes": processes,
            "rules_path": self.rules_path,
            "eve_path": self.eve_path,
            "eve_exists": os.path.exists(self.eve_path),
        }

    def _extract_sid_map(self):
        sid_map = {}
        for rule in self.list_rules():
            match = re.search(r"sid\s*:\s*(\d+)\s*;", rule, flags=re.IGNORECASE)
            if match:
                sid_map[int(match.group(1))] = rule
        return sid_map

    def list_quarantine_events(self, limit=25, ip_filter=None):
        if limit <= 0:
            limit = 25
        if limit > 200:
            limit = 200

        if not os.path.exists(self.quarantine_log_path):
            return {
                "events": [],
                "count": 0,
                "successful_quarantine_events": 0,
                "log_path": self.quarantine_log_path,
            }

        sid_map = self._extract_sid_map()
        parsed = []
        with open(self.quarantine_log_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if (entry.get("action") or "").lower() != "quarantine":
                    continue
                entry_ip = str(entry.get("ip") or "").strip()
                if ip_filter and entry_ip != ip_filter:
                    continue
                details = entry.get("details") if isinstance(entry.get("details"), dict) else {}
                recent_sids = details.get("recent_sids") or []
                if not isinstance(recent_sids, list):
                    recent_sids = []
                trigger_sid = details.get("trigger_sid")
                sid_candidates = []
                for sid in recent_sids:
                    try:
                        sid_candidates.append(int(sid))
                    except (TypeError, ValueError):
                        continue
                try:
                    if trigger_sid is not None:
                        sid_candidates.append(int(trigger_sid))
                except (TypeError, ValueError):
                    pass
                sid_candidates = sorted(set(sid_candidates))
                matched_rules = [{"sid": sid, "rule": sid_map.get(sid, "Rule not found in current ruleset")} for sid in sid_candidates]

                parsed.append({
                    "timestamp": entry.get("timestamp"),
                    "ip": entry_ip,
                    "reason": entry.get("reason") or "Quarantine triggered",
                    "backend": (details.get("backend_used") or entry.get("backend") or "unknown"),
                    "action": "quarantine",
                    "details": details,
                    "matched_rules": matched_rules,
                    "enforced": "added" in str(details.get("apply_result") or "").lower(),
                })

        parsed.sort(key=lambda item: str(item.get("timestamp") or ""), reverse=True)
        events = parsed[:limit]
        successful_count = len([item for item in parsed if item.get("enforced")])
        return {
            "events": events,
            "count": len(events),
            "total_quarantine_events": len(parsed),
            "successful_quarantine_events": successful_count,
            "log_path": self.quarantine_log_path,
        }

# Initialize router
nat_router = NATRouter()

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    suricata = nat_router.suricata_status()
    return jsonify({
        'status': 'healthy',
        'service': 'nat-router',
        'routing_active': nat_router.running,
        'rules_path': nat_router.rules_path,
        'suricata': suricata
    })

@app.route('/start', methods=['POST'])
def start_routing():
    """Start NAT routing"""
    nat_router.start_routing()
    return jsonify({'status': 'NAT routing started'})

@app.route('/stop', methods=['POST'])
def stop_routing():
    """Stop NAT routing"""
    nat_router.stop_routing()
    return jsonify({'status': 'NAT routing stopped'})

@app.route('/status', methods=['GET'])
def get_status():
    """Get routing status"""
    return jsonify({
        'routing_active': nat_router.running,
        'rules_path': nat_router.rules_path,
        'timestamp': time.time()
    })


@app.route('/api/list-rules', methods=['GET'])
def list_rules():
    try:
        rules = nat_router.list_rules()
        return jsonify({'status': 'ok', 'rules': rules, 'count': len(rules)})
    except Exception as e:
        logger.error(f"Rule list error: {str(e)}")
        return jsonify({'status': 'error', 'error': str(e)}), 500


@app.route('/api/add-rule', methods=['POST'])
def add_rule():
    data = request.get_json(silent=True) or {}
    try:
        result = nat_router.add_rule(data.get('rule'))
        reload_result = nat_router.reload_suricata()
        return jsonify({
            'status': 'ok',
            'result': result,
            'reload': reload_result
        })
    except ValueError as e:
        return jsonify({'status': 'error', 'error': str(e)}), 400
    except Exception as e:
        logger.error(f"Rule add error: {str(e)}")
        return jsonify({'status': 'error', 'error': str(e)}), 500


@app.route('/api/remove-rule', methods=['POST'])
def remove_rule():
    data = request.get_json(silent=True) or {}
    try:
        result = nat_router.remove_rule_by_sid(data.get('sid'))
        reload_result = nat_router.reload_suricata() if result.get('removed', 0) > 0 else {'reloaded': False, 'reason': 'nothing removed'}
        return jsonify({
            'status': 'ok',
            'result': result,
            'reload': reload_result
        })
    except ValueError as e:
        return jsonify({'status': 'error', 'error': str(e)}), 400
    except Exception as e:
        logger.error(f"Rule remove error: {str(e)}")
        return jsonify({'status': 'error', 'error': str(e)}), 500


@app.route('/api/reload-suricata', methods=['POST'])
def reload_suricata():
    try:
        result = nat_router.reload_suricata()
        status_code = 200 if result.get('reloaded') else 500
        return jsonify({'status': 'ok' if result.get('reloaded') else 'error', 'result': result}), status_code
    except Exception as e:
        logger.error(f"Suricata reload error: {str(e)}")
        return jsonify({'status': 'error', 'error': str(e)}), 500


@app.route('/api/quarantine-events', methods=['GET'])
def list_quarantine_events():
    try:
        limit = int(request.args.get('limit', 25))
    except (TypeError, ValueError):
        limit = 25
    ip_filter = (request.args.get('ip') or '').strip() or None

    try:
        payload = nat_router.list_quarantine_events(limit=limit, ip_filter=ip_filter)
        payload["status"] = "ok"
        return jsonify(payload)
    except Exception as e:
        logger.error(f"Quarantine events error: {str(e)}")
        return jsonify({'status': 'error', 'error': str(e)}), 500


if __name__ == '__main__':
    # Auto-start routing
    nat_router.start_routing()

    # Start Flask API
    app.run(host='0.0.0.0', port=5050, debug=False)
