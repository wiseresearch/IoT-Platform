/* ==========================================================================
   FleetOps core — single normalized fleet store + realtime ingestion.
   Exposes window.FleetOps; visualization modules register on window.FleetViews.
   ========================================================================== */
(function () {
    'use strict';

    var API = (typeof API_BASE !== 'undefined') ? API_BASE : '/api';
    var SVGNS = 'http://www.w3.org/2000/svg';
    var HEALTH = ['healthy', 'degraded', 'offline'];
    var PALETTE = ['#2dd4bf', '#38bdf8', '#a78bfa', '#fbbf24', '#fb7185', '#f472b6', '#4ade80', '#94a3b8'];
    var ZONE_OF = {
        camera: 'Perimeter', lock: 'Perimeter', sensor: 'Perimeter', doorbell: 'Perimeter', iot: 'Perimeter',
        thermostat: 'Environment', light: 'Environment', plug: 'Environment', speaker: 'Environment', media: 'Environment',
        router: 'Infrastructure', hub: 'Infrastructure', nas: 'Infrastructure', printer: 'Infrastructure', tv: 'Infrastructure', gateway: 'Infrastructure',
        computer: 'Infrastructure', phone: 'Infrastructure', tablet: 'Infrastructure'
    };

    var state = {
        mounted: false,
        visible: false,
        mode: 'live',
        fleet: null,
        devices: [],
        gates: [],
        incidents: [],
        devByKey: {},
        catByKey: {},
        gatewayById: {},
        selected: null,
        hovered: null,
        expandedGateways: {},
        expandedCategories: {},
        events: [],
        es: null,
        demoTimer: null,
        detailToken: 0,
        drawerFor: null,
        lastSeq: 0
    };

    var views = window.FleetViews = window.FleetViews || {};

    /* Fan-out helpers: every visualization receives the same selection,
       update and animation signals, which is what keeps the workspace in sync. */
    function eachView(fn) {
        // Capture the caller's payload before entering forEach: inside the
        // callback `arguments` is (suffix, index, array), which silently
        // forwarded view indexes instead of the selection key.
        var payload = Array.prototype.slice.call(arguments, 1);
        ['Topology', 'Bullseye', 'Matrix'].forEach(function (suffix) {
            var f = views[fn + suffix];
            if (typeof f === 'function') f.apply(views, payload);
        });
    }
    function updateAll() { eachView('update'); }
    function highlightAll(key) { eachView('highlight', key); }
    function focusAll(key) { eachView('focus', key); }
    function pulseAll(key, kind) { eachView('pulse', key, kind); }
    function roamAll(key, fromId, toId) { eachView('roam', key, fromId, toId); }

    /* ---------------- utils ---------------- */
    function $(id) { return document.getElementById(id); }
    function esc(value) {
        return String(value == null ? '' : value)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }
    function num(value, fallback) {
        var n = Number(value);
        return isFinite(n) ? n : (fallback == null ? 0 : fallback);
    }
    function clamp(v, lo, hi) { return Math.max(lo, Math.min(hi, v)); }
    function timeAgo(ts) {
        var t = Date.parse(ts);
        if (!isFinite(t)) return '';
        var s = Math.max(0, (Date.now() - t) / 1000);
        if (s < 45) return 'just now';
        if (s < 3600) return Math.round(s / 60) + 'm ago';
        if (s < 86400) return Math.round(s / 3600) + 'h ago';
        return Math.round(s / 86400) + 'd ago';
    }
    function clock(ts) {
        var d = ts ? new Date(ts) : new Date();
        if (isNaN(d.getTime())) d = new Date();
        return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    }
    function fmtMs(v) {
        if (v == null || !isFinite(Number(v))) return '—';
        var n = Number(v);
        return n >= 100 ? Math.round(n) + ' ms' : n.toFixed(n >= 10 ? 1 : 2) + ' ms';
    }
    function healthOf(dev) {
        var h = (dev && dev.health) || {};
        var s = String(h.state || dev.health_state || '').toLowerCase();
        if (s === 'healthy' || s === 'degraded' || s === 'offline') return s;
        if (dev.quarantined || dev.discovered_state === 'quarantined') return 'degraded';
        return dev.reachable === false ? 'offline' : 'healthy';
    }
    function stateClass(dev) {
        if (dev && dev.quarantined) return 'is-quarantined';
        return 'is-' + healthOf(dev);
    }
    function catOf(dev) {
        return {
            key: (dev && (dev.category || dev.device_type || 'unknown')) || 'unknown',
            label: (dev && (dev.category_label || dev.type || dev.category || 'Unclassified')) || 'Unclassified'
        };
    }
    function zoneOf(category) { return ZONE_OF[category] || 'Unclassified'; }
    function categoryColor(key) {
        var idx = 0;
        state.devices.forEach(function (d, i) {
            if (!d.is_gateway && d.category === key) { idx = i; return; }
        });
        var cats = {};
        var n = 0;
        state.devices.forEach(function (d) {
            if (d.is_gateway) return;
            if (!(d.category in cats)) { cats[d.category] = n; n++; }
        });
        return PALETTE[(cats[key] || 0) % PALETTE.length];
    }
    function toast(message) {
        var el = $('fleet-toast');
        if (!el) return;
        el.textContent = message;
        el.classList.add('is-on');
        clearTimeout(toast._t);
        toast._t = setTimeout(function () { el.classList.remove('is-on'); }, 2200);
    }
    function svgEl(tag, attrs) {
        var el = document.createElementNS(SVGNS, tag);
        if (attrs) Object.keys(attrs).forEach(function (k) { el.setAttribute(k, attrs[k]); });
        return el;
    }

    /* ---------------- data ---------------- */
    function normalize(raw) {
        var devices = (raw && raw.devices) || [];
        var gateways = (raw && raw.gateways) || [];
        var incidents = (raw && raw.incidents) || [];
        return {
            seq: raw && raw.seq,
            generated_at: (raw && raw.generated_at) || new Date().toISOString(),
            collector: raw && raw.collector,
            summary: (raw && raw.summary) || {},
            devices: devices,
            gateways: gateways,
            clusters: (raw && raw.clusters) || [],
            links: (raw && raw.links) || [],
            incidents: incidents.filter(function (i) {
                var s = String(i.status || 'open').toLowerCase();
                return s === 'open' || s === 'active' || s === 'investigating';
            })
        };
    }

    function applyFleet(raw, origin) {
        var fleet = normalize(raw);
        if (!fleet.devices.length && state.mode === 'live') {
            // keep whatever we had; an empty payload is usually a transient DB read.
            return;
        }
        var prevGw = {};
        state.devices.forEach(function (d) { prevGw[d.key] = d.gateway_id; });
        var prevDevices = state.devByKey;
        state.fleet = fleet;
        state.devices = fleet.devices;
        state.gates = fleet.gateways;
        state.incidents = fleet.incidents;
        state.lastSeq = fleet.seq || state.lastSeq;

        var byKey = {}, byGw = {}, catByKey = {};
        fleet.devices.forEach(function (d) {
            byKey[d.key] = d;
            var cat = catOf(d);
            d.category = cat.key;
            d.category_label = cat.label;
            d._state = healthOf(d);
            catByKey[cat.key] = cat;
        });
        fleet.gateways.forEach(function (g) {
            g._state = String(g.state || 'healthy').toLowerCase();
            if (g._state === 'unknown') g._state = 'healthy';
            byGw[g.id] = g;
            // gateway is a first-class selection target so every view can link to it
            byKey[g.id] = {
                key: g.id, name: g.name || g.ip || 'Gateway', ip: g.ip, hostname: g.name,
                is_gateway: true, category: 'network', category_label: 'Infrastructure',
                gateway_id: g.id, gateway_name: g.name, type: 'gateway', risk: 'low',
                health: { state: g._state, score: g.device_count ? Math.round((num(g.healthy) / Math.max(1, num(g.device_count))) * 100) : 100, latency_ms: g.latency_ms, loss_pct: g.packet_loss },
                quarantined: false, _state: g._state
            };
            catByKey.network = catByKey.network || { key: 'network', label: 'Infrastructure' };
        });
        state.devByKey = byKey;
        state.gatewayById = byGw;
        state.catByKey = catByKey;

        // default expansion: all gateways; categories only when the canvas stays readable
        if (!state._seeded) {
            fleet.gateways.forEach(function (g) { state.expandedGateways[g.id] = true; });
            if (fleet.devices.length <= 30) {
                Object.keys(catByKey).forEach(function (k) { state.expandedCategories[k] = true; });
            }
            state._seeded = true;
        } else {
            fleet.gateways.forEach(function (g) { if (!(g.id in state.expandedGateways)) state.expandedGateways[g.id] = true; });
        }

        // keep selection valid, resolve key if the store migrated from ip: to mac:
        if (state.selected && !byKey[state.selected] && !groupInfo(state.selected)) {
            var old = prevDevices[state.selected];
            if (old && old.ip) {
                var match = fleet.devices.filter(function (d) { return d.ip === old.ip; })[0];
                if (match) state.selected = match.key;
            }
            if (state.selected && !byKey[state.selected] && !groupInfo(state.selected)) state.selected = null;
        }
        if (state.hovered && !byKey[state.hovered] && !groupInfo(state.hovered)) state.hovered = null;

        renderAll();
        renderKpis();
        renderTicker();
        updateConn(origin === 'sim' ? 'sim' : 'live');

        if (state.selected) renderDrawer(state.devByKey[state.selected], null, true);
        updateAll();
    }

    function patchDevice(device) {
        if (!device || !device.key || !state.devByKey[device.key]) return;
        var prev = state.devByKey[device.key];
        var gwChanged = device.gateway_id && prev.gateway_id && device.gateway_id !== prev.gateway_id;
        var merged = Object.assign({}, prev, device);
        merged.health = Object.assign({}, prev.health || {}, device.health || {});
        merged._state = healthOf(merged);
        state.devByKey[device.key] = merged;
        state.devices = state.devices.map(function (d) { return d.key === device.key ? merged : d; });
        if (gwChanged) {
            roamAll(device.key, prev.gateway_id, device.gateway_id);
        }
        updateAll();
    }

    /* ---------------- events ---------------- */
    function eventMeta(msg) {
        var type = String((msg && msg.type) || 'event');
        var dev = (msg && (msg.device || msg.previous)) || {};
        var name = dev.name || dev.hostname || dev.ip || 'device';
        var detail = msg && msg.detail ? String(msg.detail) : '';
        var meta = { type: type, ts: (msg && msg.ts) || new Date().toISOString(), key: (msg && msg.device_key) || dev.key || null, sev: '' };
        if (type === 'device.roamed') {
            meta.title = name + ' roamed';
            meta.detail = (msg.from_gateway_name || msg.from_gateway || '?') + ' → ' + (msg.to_gateway_name || msg.to_gateway || '?');
            meta.sev = 'sev-roam';
        } else if (type === 'device.discovered') {
            meta.title = 'New device discovered';
            meta.detail = (dev.ip || '') + (msg.quarantined ? ' · quarantined' : '');
            meta.sev = 'sev-good';
        } else if (type === 'device.identified') {
            meta.title = name + ' fingerprinted';
            meta.detail = msg.detail || 'quarantine released';
            meta.sev = 'sev-good';
        } else if (type === 'device.lost') {
            meta.title = (dev.name || dev.ip || 'Device') + ' went dark';
            meta.detail = detail || 'no longer responding';
            meta.sev = 'sev-high';
        } else if (type === 'health.degraded') {
            meta.title = name + ' degraded';
            meta.detail = detail || ('score ' + num(dev.health && dev.health.score).toFixed(0));
            meta.sev = 'sev-medium';
        } else if (type === 'health.recovered') {
            meta.title = name + ' recovered';
            meta.detail = detail || 'back in healthy range';
            meta.sev = 'sev-good';
        } else if (type === 'gateway.outage') {
            meta.title = (msg.gateway && msg.gateway.name) || 'Gateway outage';
            meta.detail = detail || 'upstream unreachable';
            meta.sev = 'sev-high';
        } else if (type === 'gateway.online') {
            meta.title = (msg.gateway && msg.gateway.name) || 'Gateway online';
            meta.detail = detail || 'link restored';
            meta.sev = 'sev-good';
        } else if (type.indexOf('incident') === 0) {
            meta.title = msg.title || 'Incident updated';
            meta.detail = detail || (msg.severity || '');
            meta.sev = String(msg.severity || '').toLowerCase() === 'high' ? 'sev-high' : 'sev-medium';
        } else if (type === 'telemetry.batch') {
            return null;
        } else {
            meta.title = type.replace(/\./g, ' ');
            meta.detail = detail;
            meta.sev = '';
        }
        return meta;
    }

    function pushEvent(msg) {
        var meta = eventMeta(msg);
        if (!meta) return;
        state.events.unshift(meta);
        state.events = state.events.slice(0, 18);
        renderTicker();
        if (meta.key) pulseAll(meta.key, meta.type);
        if (meta.type === 'device.roamed' && msg.device) {
            patchDevice(msg.device);
        } else if (msg.device && msg.device.key) {
            patchDevice(msg.device);
        }
    }

    function renderTicker() {
        var track = $('fleet-ticker-track');
        if (!track) return;
        if (!state.events.length) {
            track.innerHTML = '<span class="fleet-ticker-empty">Waiting for fleet events…</span>';
            return;
        }
        track.innerHTML = state.events.slice(0, 10).map(function (e) {
            return '<span class="fleet-tick ' + e.sev + '" title="' + esc(e.detail) + '">' +
                '<i class="t-dot"></i><b>' + esc(e.title) + '</b>' +
                (e.detail ? '<span>' + esc(e.detail) + '</span>' : '') +
                '<span class="t-time">' + esc(clock(e.ts)) + '</span></span>';
        }).join('');
    }

    /* ---------------- KPIs ---------------- */
    function counts() {
        var c = { total: 0, healthy: 0, degraded: 0, offline: 0, quarantined: 0, unidentified: 0, incidents: state.incidents.length, gateways: state.gates.length };
        state.devices.forEach(function (d) {
            c.total++;
            var s = healthOf(d);
            if (s === 'healthy') c.healthy++;
            else if (s === 'degraded') c.degraded++;
            else c.offline++;
            if (d.quarantined) { c.quarantined++; c.unidentified++; }
        });
        if (state.fleet && state.fleet.summary && Object.keys(state.fleet.summary).length) {
            var s = state.fleet.summary;
            c.total = num(s.total, c.total);
            c.healthy = num(s.healthy, c.healthy);
            c.degraded = num(s.degraded, c.degraded);
            c.offline = num(s.offline, c.offline);
            c.quarantined = num(s.quarantined, c.quarantined);
            c.unidentified = num(s.unidentified, c.quarantined);
            c.incidents = num(s.active_incidents, c.incidents);
            c.gateways = num(s.gateways, c.gateways);
        }
        c.avgLatency = state.fleet && state.fleet.summary ? state.fleet.summary.avg_latency_ms : null;
        return c;
    }

    function renderKpis() {
        var el = $('fleet-kpis');
        if (!el) return;
        var c = counts();
        var pct = c.total ? Math.round((c.healthy / c.total) * 100) : 0;
        var tiles = [
            { k: '', label: 'Devices in fleet', value: c.total, sub: c.gateways + ' gateway' + (c.gateways === 1 ? '' : 's') + ' · ' + state.fleet.clusters.length + ' clusters' },
            { k: 'is-healthy', label: 'Healthy', value: c.healthy, sub: pct + '% of fleet nominal' },
            { k: 'is-degraded', label: 'Degraded', value: c.degraded, sub: c.avgLatency != null ? 'avg ' + fmtMs(c.avgLatency) : 'latency watch' },
            { k: 'is-offline', label: 'Offline', value: c.offline, sub: 'unreachable now' },
            { k: 'is-unidentified', label: 'Quarantined', value: c.quarantined, sub: 'awaiting fingerprint' },
            { k: 'is-incident', label: 'Active incidents', value: c.incidents, sub: 'open · last 24h' }
        ];
        el.innerHTML = tiles.map(function (t) {
            return '<div class="fleet-kpi ' + t.k + '">' +
                '<div class="fleet-kpi-label">' + esc(t.label) + '</div>' +
                '<div class="fleet-kpi-value">' + t.value + '</div>' +
                '<div class="fleet-kpi-sub">' + esc(t.sub) + '</div></div>';
        }).join('');
        var hc = $('fleet-hero-count');
        if (hc) hc.textContent = c.total;
    }

    function updateConn(kind) {
        var el = $('fleet-conn');
        if (!el) return;
        el.className = 'fleet-conn' + (kind === 'live' ? ' is-live' : kind === 'sim' ? ' is-sim' : kind === 'down' ? ' is-down' : '');
        el.textContent = kind === 'live' ? 'live stream' : kind === 'sim' ? 'simulation' : kind === 'down' ? 'stream offline' : 'connecting…';
    }

    /* ---------------- selection / hover ----------------
       Interaction model:
         hover  -> transient highlight in every view, never a selection
         click  -> pin the highlighted device or group (no drawer)
         click again on the same target -> open its diagnostics drawer
       A group can be a gateway cluster, a category cluster inside a gateway,
       a fleet-wide category (bullseye wedge) or a matrix zone. */
    function clusterKey(gatewayId, category) {
        return 'cluster:' + (gatewayId || '*') + '|' + category;
    }

    function groupInfo(key) {
        if (!key || typeof key !== 'string') return null;
        var kind, members = [], gatewayId = null, category = null, zone = null, label = '';
        if (key.indexOf('cluster:') === 0) {
            var body = key.slice(8), sep = body.indexOf('|');
            if (sep < 0) return null;
            gatewayId = body.slice(0, sep) || '*';
            category = body.slice(sep + 1);
            if (!category) return null;
            members = state.devices.filter(function (d) {
                return !d.is_gateway && d.category === category && (gatewayId === '*' || d.gateway_id === gatewayId);
            });
            if (!members.length) return null;
            kind = 'category';
            label = (state.catByKey[category] && state.catByKey[category].label) || category;
            if (gatewayId === '*') gatewayId = null;
        } else if (key.indexOf('zone:') === 0) {
            zone = key.slice(5);
            members = state.devices.filter(function (d) { return !d.is_gateway && zoneOf(d.category) === zone; });
            if (!members.length) return null;
            kind = 'zone';
            label = zone;
        } else {
            var gd = state.devByKey[key];
            if (!gd || !gd.is_gateway) return null;
            gatewayId = gd.key;
            members = state.devices.filter(function (d) { return !d.is_gateway && d.gateway_id === gd.key; });
            kind = 'gateway';
            label = gd.name || gd.ip || 'Gateway';
        }
        var memberKeys = {}, gatewayIds = {}, categories = {};
        members.forEach(function (d) {
            memberKeys[d.key] = 1;
            gatewayIds[d.gateway_id] = 1;
            categories[d.category] = 1;
        });
        return {
            kind: kind, key: key, label: label, gateway_id: gatewayId,
            category: category, zone: zone, members: members,
            memberKeys: memberKeys, gatewayIds: gatewayIds, categories: categories
        };
    }

    /* A pinned selection and a live hover are two independent focuses: the pin
       must stay lit while the cursor previews something else, and vice versa.
       Return both (pin first, duplicate collapsed) so every view can dim
       against their union instead of letting hover replace the selection. */
    function focusTargets() {
        var keys = [];
        if (state.selected) keys.push(state.selected);
        if (state.hovered && state.hovered !== state.selected) keys.push(state.hovered);
        return keys.map(function (key) {
            return { key: key, grp: groupInfo(key), dev: state.devByKey[key] || null };
        });
    }

    function groupState(grp) {
        if (grp.kind === 'gateway') {
            var gate = state.gatewayById[grp.gateway_id];
            if (gate && gate._state === 'offline') return 'offline';
        }
        var bad = false;
        grp.members.forEach(function (d) {
            if (healthOf(d) !== 'healthy') bad = true;
        });
        return bad ? 'degraded' : 'healthy';
    }

    function select(key, opts) {
        opts = opts || {};
        var grp = groupInfo(key);
        if (!state.devByKey[key] && !grp) return;
        var already = state.selected === key;
        state.selected = key;
        if (opts.reveal !== false) reveal(key);
        highlightAll(key);
        if (opts.open === true || (already && opts.open !== false)) {
            openTarget(key);
        } else if (!already && state.drawerFor) {
            closeDrawer();
        }
    }

    function reveal(key) {
        var grp = groupInfo(key);
        if (grp) {
            var structure = false;
            Object.keys(grp.gatewayIds).forEach(function (id) {
                if (!state.expandedGateways[id]) { state.expandedGateways[id] = true; structure = true; }
            });
            if (grp.kind === 'category') {
                if (!state.expandedCategories[grp.category]) state.expandedCategories[grp.category] = true;
            } else if (grp.kind === 'zone') {
                Object.keys(grp.categories).forEach(function (c) { state.expandedCategories[c] = true; });
            }
            if (structure) rebuildTopology(); else renderAll();
            return;
        }
        var d = state.devByKey[key];
        if (!d) return;
        if (d.is_gateway && !state.expandedGateways[d.key]) state.expandedGateways[d.key] = true;
        if (d.gateway_id && !state.expandedGateways[d.gateway_id]) state.expandedGateways[d.gateway_id] = true;
        if (!d.is_gateway && !state.expandedCategories[d.category]) {
            state.expandedCategories[d.category] = true;
            renderAll();
        }
        focusAll(key);
    }

    /* Hover used to repaint all three views synchronously on every mouseenter,
       so sweeping the cursor across a dense topology queued hundreds of full
       highlight passes per second. Coalesce them into one pass per frame. */
    var hoverRAF = 0;
    function queueHighlight() {
        if (hoverRAF) return;
        hoverRAF = requestAnimationFrame(function () {
            hoverRAF = 0;
            highlightAll(state.selected || state.hovered);
        });
    }

    function hover(key) {
        /* While the diagnostics drawer is pinned, the cursor sweeping the
           blurred background must not repaint 120 nodes per frame. */
        if (state.drawerFor) return;
        state.hovered = key || null;
        queueHighlight();
    }

    function clearHover() {
        state.hovered = null;
        if (state.drawerFor) return;
        queueHighlight();
    }

    function clearSelection() {
        state.selected = null;
        state.hovered = null;
        closeDrawer();
        highlightAll(null);
    }

    /* ---------------- drawer ---------------- */
    function openDrawer() {
        var drawer = $('fleet-drawer'), scrim = $('fleet-scrim');
        if (!drawer) return;
        drawer.classList.add('is-on');
        drawer.setAttribute('aria-hidden', 'false');
        if (scrim) scrim.classList.add('is-on');
        document.body.classList.add('drawer-open');
    }

    function closeDrawer() {
        var drawer = $('fleet-drawer'), scrim = $('fleet-scrim');
        if (drawer) { drawer.classList.remove('is-on'); drawer.setAttribute('aria-hidden', 'true'); }
        if (scrim) scrim.classList.remove('is-on');
        document.body.classList.remove('drawer-open');
        state.drawerFor = null;
    }

    function openTarget(key) {
        var grp = groupInfo(key);
        if (grp) { openGroupDrawer(grp); return; }
        var dev = state.devByKey[key];
        if (!dev) return;
        renderDrawer(dev, null, false);
        openDrawer();
    }

    function openGroupDrawer(grp) {
        var head = $('fleet-drawer-head'), body = $('fleet-drawer-body');
        if (!head || !body) return;
        state.drawerFor = grp.key;
        var isGw = grp.kind === 'gateway';
        var isZone = grp.kind === 'zone';
        var gate = grp.gateway_id ? state.gatewayById[grp.gateway_id] : null;
        var gateName = gate ? (gate.name || gate.ip || grp.gateway_id) : null;
        var gs = groupState(grp);
        var counts = { healthy: 0, degraded: 0, offline: 0, quarantined: 0 };
        var latSum = 0, latN = 0;
        grp.members.forEach(function (d) {
            var hs = healthOf(d);
            counts[hs] = (counts[hs] || 0) + 1;
            if (d.quarantined) counts.quarantined++;
            var lat = d.health && d.health.latency_ms != null ? num(d.health.latency_ms) : (d.latency_ms != null ? num(d.latency_ms) : null);
            if (lat != null && isFinite(lat)) { latSum += lat; latN++; }
        });

        var title, eyebrow, bits;
        if (isGw) {
            title = grp.label;
            eyebrow = 'Gateway diagnostics';
            bits = [gate && gate.ip ? gate.ip : '', 'parent cluster'];
        } else if (isZone) {
            title = grp.zone + ' zone';
            eyebrow = 'Zone diagnostics';
            bits = [Object.keys(grp.gatewayIds).length + ' gateways', 'telemetry zone'];
        } else if (grp.gateway_id) {
            title = grp.label;
            eyebrow = 'Device group diagnostics';
            bits = [gateName || grp.gateway_id, 'category cluster'];
        } else {
            title = grp.label;
            eyebrow = 'Device group diagnostics';
            bits = [Object.keys(grp.gatewayIds).length + ' gateways', 'fleet-wide cluster'];
        }
        var ipLine = bits.map(function (b) { return '<span>' + esc(b) + '</span>'; }).join('<span>·</span>');
        head.innerHTML = '<div class="fleet-drawer-top"><div>' +
            '<div class="fleet-drawer-eyebrow">' + eyebrow + '</div>' +
            '<h2>' + esc(title) + '</h2>' +
            '<div class="fleet-drawer-ip">' + ipLine + '</div>' +
            '</div><button class="fleet-drawer-close" onclick="FleetOps.closeDrawer()" aria-label="Close"><i class="fas fa-xmark"></i></button></div>' +
            '<div class="fleet-drawer-pills">' +
            '<span class="fleet-pill is-' + esc(gs) + '">' + esc(gs) + '</span>' +
            '<span class="fleet-pill">' + grp.members.length + ' devices</span>' +
            (counts.offline ? '<span class="fleet-pill is-offline">' + counts.offline + ' offline</span>' : '') +
            (counts.quarantined ? '<span class="fleet-pill is-quarantined">' + counts.quarantined + ' quarantined</span>' : '') +
            '</div>';

        var ordered = grp.members.slice().sort(function (a, b) {
            var order = { offline: 0, degraded: 1, healthy: 2 };
            return order[healthOf(a)] - order[healthOf(b)] || String(a.name || '').localeCompare(String(b.name || ''));
        });
        body.innerHTML = '<div class="fleet-metrics">' +
            metric('Devices', grp.members.length) +
            metric('Healthy', counts.healthy) +
            metric('Degraded', counts.degraded) +
            metric('Offline', counts.offline) +
            metric('Quarantined', counts.quarantined) +
            metric('Avg latency', latN ? fmtMs(latSum / latN) : '—') +
            '</div><div class="fleet-section"><div class="fleet-section-head"><h3>Group members</h3><span>top 12 by health</span></div><div class="fleet-facts">' +
            ordered.slice(0, 12).map(function (d) {
                return '<div class="fleet-fact"><span><i class="fas fa-circle" style="font-size:.4rem;color:var(--fl-' + healthOf(d) + ')"></i> ' + esc(d.name || d.ip) + '</span><b>' + esc(d.ip || '') + '</b></div>';
            }).join('') +
            '</div></div><div class="fleet-drawer-actions"><button class="fleet-act is-primary" id="fleet-group-action">' +
            (isGw ? (state.expandedGateways[grp.gateway_id] ? 'Collapse gateway' : 'Expand gateway')
                : isZone ? 'Expand zone members'
                    : (state.expandedCategories[grp.category] ? 'Collapse devices' : 'Expand devices')) +
            '</button></div>' +
            '<div class="fleet-drawer-note">First click pins a target. Click the same target again to reopen this panel. Hover only highlights.</div>';

        var action = $('fleet-group-action');
        if (action) {
            action.addEventListener('click', function () {
                if (isGw) {
                    state.expandedGateways[grp.gateway_id] = !state.expandedGateways[grp.gateway_id];
                } else if (isZone) {
                    Object.keys(grp.categories).forEach(function (c) { state.expandedCategories[c] = true; });
                    Object.keys(grp.gatewayIds).forEach(function (id) { state.expandedGateways[id] = true; });
                } else {
                    state.expandedCategories[grp.category] = !state.expandedCategories[grp.category];
                }
                rebuildTopology();
                closeDrawer();
            });
        }
        openDrawer();
    }

    function renderDrawer(dev, detail, quiet) {
        var body = $('fleet-drawer-body');
        var head = $('fleet-drawer-head');
        if (!body || !head || !dev) return;
        state.drawerFor = dev.key;
        var h = dev.health || {};
        var hstate = healthOf(dev);
        var c = catOf(dev);
        head.innerHTML =
            '<div class="fleet-drawer-top"><div>' +
            '<div class="fleet-drawer-eyebrow">Device diagnostics</div>' +
            '<h2>' + esc(dev.name || dev.hostname || 'Unnamed device') + '</h2>' +
            '<div class="fleet-drawer-ip"><span>' + esc(dev.ip || 'no address') + '</span><span>·</span><span>' + esc(dev.gateway_name || 'unassigned gateway') + '</span></div>' +
            '</div><button class="fleet-drawer-close" onclick="FleetOps.closeDrawer()" aria-label="Close"><i class="fas fa-xmark"></i></button></div>' +
            '<div class="fleet-drawer-pills">' +
            '<span class="fleet-pill is-' + esc(hstate) + '"><i class="fas fa-circle" style="font-size:.45rem"></i>' + esc(hstate) + '</span>' +
            '<span class="fleet-pill">' + esc(c.label) + '</span>' +
            (dev.quarantined ? '<span class="fleet-pill is-quarantined">quarantined</span>' : '') +
            (dev.risk ? '<span class="fleet-pill">' + esc(dev.risk) + ' risk</span>' : '') +
            (dev.vuln_count ? '<span class="fleet-pill">' + num(dev.vuln_count) + ' CVEs</span>' : '') +
            '</div>';

        var score = h.score != null ? Math.round(h.score) : '—';
        var latency = h.latency_ms != null ? fmtMs(h.latency_ms) : (dev.latency_ms != null ? fmtMs(dev.latency_ms) : '—');
        var loss = h.loss_pct != null ? num(h.loss_pct).toFixed(1) + '%' : (h.packet_loss != null ? num(h.packet_loss).toFixed(1) + '%' : '—');
        var seen = dev.last_seen ? timeAgo(dev.last_seen) : 'unknown';
        var ports = dev.open_ports != null ? num(dev.open_ports) : (dev.ports ? dev.ports.length : 0);

        var html = '<div class="fleet-metrics">' +
            metric('Health score', score) +
            metric('Latency', latency) +
            metric('Packet loss', loss) +
            metric('Open ports', ports) +
            metric('Vulnerabilities', dev.vuln_count != null ? num(dev.vuln_count) : '—') +
            metric('Last seen', seen) +
            '</div>';

        html += '<div class="fleet-section"><div class="fleet-section-head"><h3>Responsiveness · recent probes</h3><span>' + (detail && detail.latency_series ? detail.latency_series.length : 0) + ' samples</span></div>';
        if (detail && detail.latency_series && detail.latency_series.length > 1) {
            html += sparkline(detail.latency_series, hstate);
        } else if (detail) {
            html += '<div class="fleet-spark-empty">Collecting probe history…</div>';
        } else {
            html += '<div class="fleet-spark-empty"><i class="fas fa-circle-notch fa-spin"></i>&nbsp; loading diagnostics…</div>';
        }
        html += '</div>';

        html += '<div class="fleet-section"><div class="fleet-section-head"><h3>Identity</h3><span>' + esc(dev.type || c.label) + '</span></div>' +
            '<div class="fleet-facts">' +
            fact('Hostname', dev.hostname) +
            fact('MAC address', dev.mac) +
            fact('Vendor / OS', [dev.vendor, dev.os].filter(Boolean).join(' · ')) +
            fact('Link', dev.link_kind ? dev.link_kind + (dev.is_gateway ? ' · gateway' : '') : (dev.is_gateway ? 'gateway' : null)) +
            fact('Battery', dev.battery != null ? dev.battery + '%' : null) +
            fact('First seen', dev.first_seen ? new Date(dev.first_seen).toLocaleString() : null) +
            '</div></div>';

        var incs = (detail && detail.incidents) || state.incidents.filter(function (i) {
            return (i.device_keys || []).indexOf(dev.key) >= 0;
        });
        if (incs.length) {
            html += '<div class="fleet-section"><div class="fleet-section-head"><h3>Active incidents</h3><span>' + incs.length + ' linked</span></div>';
            incs.slice(0, 4).forEach(function (i) {
                var sev = String(i.severity || '').toLowerCase();
                html += '<div class="fleet-incident ' + (sev === 'high' || sev === 'critical' ? 'is-high' : '') + '">' +
                    '<b>' + esc(i.title || i.description || 'Incident') + '</b>' +
                    '<span>' + esc((i.severity || 'info') + ' · ' + (i.status || 'open') + ' · ' + (i.created_at ? timeAgo(i.created_at) : '')) + '</span></div>';
            });
            html += '</div>';
        }

        html += '<div class="fleet-section"><div class="fleet-section-head"><h3>Recent event log</h3><span>unified stream</span></div>';
        var timeline = (detail && detail.events) || [];
        if (timeline.length) {
            html += '<div class="fleet-timeline">' + timeline.slice(0, 7).map(function (e) {
                var type = String(e.type || e.alert || e.channel || 'event');
                var kind = /roam/i.test(type) ? 'is-roam' : /alert|degrad|outage|lost/i.test(type + ' ' + (e.detail || '')) ? 'is-alert' : /recover|discover|identif/i.test(type) ? 'is-good' : '';
                var title = e.detail || e.message || (e.alert ? e.alert + ' alert' : type.replace(/\./g, ' '));
                return '<div class="fleet-tl-item ' + kind + '"><i class="fleet-tl-dot"></i><div class="fleet-tl-copy"><b>' + esc(title) + '</b><span>' + esc(type.replace(/\./g, ' ')) + ' · ' + esc(timeAgo(e.ts || e.occurred_at || e.created_at)) + '</span></div></div>';
            }).join('') + '</div>';
        } else {
            html += '<div class="fleet-spark-empty">No events recorded for this device yet.</div>';
        }
        html += '</div>';

        html += '<div class="fleet-drawer-actions">' +
            '<button class="fleet-act is-primary" onclick="FleetOps.locate(\'' + esc(dev.key).replace(/'/g, "\\'") + '\')"><i class="fas fa-crosshairs"></i> Locate in all views</button>' +
            '<button class="fleet-act" onclick="FleetOps.copyIp(\'' + esc(dev.ip || '') + '\')"><i class="fas fa-copy"></i> Copy IP</button>' +
            '</div><div class="fleet-drawer-note">Diagnostic context is shared across topology, bullseye and matrix. Hovering any representation opens this panel too.</div>';

        body.innerHTML = html;
        body.scrollTop = 0;

        if (!detail) {
            var token = ++state.detailToken;
            fetch(API + '/fleet/device/' + encodeURIComponent(dev.key), { cache: 'no-store' })
                .then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
                .then(function (payload) {
                    if (token !== state.detailToken || state.selected !== dev.key) return;
                    renderDrawer(state.devByKey[dev.key] || dev, payload, true);
                })
                .catch(function () {
                    if (token !== state.detailToken) return;
                    var el = body.querySelector('.fleet-spark-empty');
                    if (el) el.textContent = 'Diagnostic feed unavailable — showing snapshot data only.';
                });
        }
    }

    function metric(label, value) {
        return '<div class="fleet-metric"><span>' + esc(label) + '</span><b>' + esc(value) + '</b></div>';
    }
    function fact(label, value) {
        if (!value) return '';
        return '<div class="fleet-fact"><span>' + esc(label) + '</span><b>' + esc(value) + '</b></div>';
    }

    function sparkline(values, hstate) {
        var w = 340, hgt = 64, pad = 6;
        var vals = values.map(Number).filter(function (v) { return isFinite(v); });
        if (!vals.length) return '<div class="fleet-spark-empty">No samples</div>';
        var max = Math.max.apply(null, vals), min = Math.min.apply(null, vals);
        var span = Math.max(1, max - min);
        var pts = vals.map(function (v, i) {
            var x = pad + (i / Math.max(1, vals.length - 1)) * (w - pad * 2);
            var y = hgt - pad - ((v - min) / span) * (hgt - pad * 3);
            return x.toFixed(1) + ',' + y.toFixed(1);
        });
        var color = hstate === 'offline' ? 'var(--fl-offline)' : hstate === 'degraded' ? 'var(--fl-degraded)' : 'var(--fl-healthy)';
        var area = 'M' + pad + ',' + (hgt - pad) + ' L' + pts.join(' L') + ' L' + (w - pad) + ',' + (hgt - pad) + ' Z';
        return '<svg class="fleet-spark" viewBox="0 0 ' + w + ' ' + hgt + '" preserveAspectRatio="none">' +
            '<path d="' + area + '" fill="' + color + '" opacity=".12"></path>' +
            '<polyline points="' + pts.join(' ') + '" fill="none" stroke="' + color + '" stroke-width="1.8" stroke-linejoin="round" stroke-linecap="round"></polyline>' +
            '<text x="' + pad + '" y="10" fill="var(--fl-faint)" font-size="7">' + min.toFixed(1) + '–' + max.toFixed(1) + ' ms</text>' +
            '</svg>';
    }

    /* ---------------- render orchestration ---------------- */
    function renderAll() {
        if (!state.mounted) return;
        if (!state._built) {
            eachView('build');
            state._built = true;
        } else {
            updateAll();
        }
    }

    function rebuildTopology() {
        if (views.buildTopology) views.buildTopology();
        updateAll();
    }

    /* ---------------- live stream ---------------- */
    function connect() {
        if (state.es) { state.es.close(); state.es = null; }
        updateConn('connecting');
        try {
            state.es = new EventSource(API + '/fleet/stream');
            state.es.onopen = function () { updateConn(state.mode === 'demo' ? 'sim' : 'live'); };
            state.es.onmessage = function (ev) {
                var msg;
                try { msg = JSON.parse(ev.data); } catch (e) { return; }
                if (!msg) return;
                if ((msg.type === 'snapshot' || msg.type === 'fleet.sync') && msg.fleet) {
                    if (state.mode === 'live') applyFleet(msg.fleet, 'stream');
                } else if (msg.type !== 'stream.error') {
                    if (state.mode === 'live') pushEvent(msg);
                }
            };
            state.es.onerror = function () {
                if (state.mode === 'live') updateConn('down');
            };
        } catch (e) {
            updateConn('down');
        }
    }

    function fetchSnapshot(silent) {
        return fetch(API + '/fleet/snapshot', { cache: 'no-store' })
            .then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
            .then(function (data) {
                if (state.mode !== 'live') return;
                applyFleet(data, 'snapshot');
                $('fleet-topo-empty').classList.remove('is-on');
                if (!silent) toast('Fleet state resynced · seq ' + (data.seq || '—'));
            })
            .catch(function (err) {
                $('fleet-topo-empty').classList.add('is-on');
                updateConn('down');
                if (!silent) toast('Fleet snapshot unavailable: ' + err.message);
            });
    }

    /* ---------------- demo fleet ---------------- */
    var DEMO_GATEWAYS = [
        { id: 'gw:10.20.0.1', name: 'HQ Core', ip: '10.20.0.1', kind: 'gateway', state: 'healthy' },
        { id: 'gw:10.20.4.1', name: 'Lab Distribution', ip: '10.20.4.1', kind: 'gateway', state: 'degraded' },
        { id: 'gw:10.20.8.1', name: 'Edge Pavilion', ip: '10.20.8.1', kind: 'gateway', state: 'healthy' }
    ];
    var DEMO_CATS = [
        { key: 'network', label: 'Network', n: 10 },
        { key: 'computer', label: 'Computers', n: 25 },
        { key: 'phone', label: 'Phones', n: 16 },
        { key: 'iot', label: 'IoT & sensors', n: 30 },
        { key: 'camera', label: 'Cameras', n: 16 },
        { key: 'printer', label: 'Printers', n: 6 },
        { key: 'media', label: 'Media', n: 9 },
        { key: 'unknown', label: 'Unidentified', n: 8 }
    ];

    function buildDemo() {
        var devices = [];
        var idx = 0;
        DEMO_CATS.forEach(function (c) {
            for (var i = 0; i < c.n; i++) {
                idx++;
                var gw = DEMO_GATEWAYS[idx % 3 === 0 ? 1 : idx % 5 === 0 ? 2 : 0];
                var quarantine = c.key === 'unknown';
                var roll = (idx * 37) % 100;
                var hstate = quarantine ? 'healthy' : roll < 74 ? 'healthy' : roll < 90 ? 'degraded' : 'offline';
                var latency = hstate === 'offline' ? null : hstate === 'degraded' ? 120 + (idx * 17) % 260 : 1.5 + (idx * 13) % 22;
                var score = hstate === 'offline' ? 0 : hstate === 'degraded' ? 30 + (idx * 7) % 28 : 72 + (idx * 11) % 27;
                var name = c.key + '-' + String(i + 1).padStart(2, '0');
                devices.push({
                    key: 'demo:' + c.key + ':' + idx,
                    name: name,
                    hostname: name + '.lab.local',
                    ip: '10.20.' + (gw === DEMO_GATEWAYS[0] ? 0 : gw === DEMO_GATEWAYS[1] ? 4 : 8) + '.' + (10 + i),
                    mac: '02:00:00:' + ('0' + Math.floor(idx / 100)).slice(-2) + ':' + ('0' + (idx % 100)).slice(-2) + ':' + ('0' + (idx % 97)).slice(-2),
                    category: c.key,
                    category_label: c.label,
                    type: c.label,
                    vendor: ['Ubiquiti', 'Apple', 'Dell', 'Samsung', 'Axis', 'HP', 'Sonos', 'Unknown'][idx % 8],
                    os: ['Linux', 'iOS', 'Windows 11', 'Android', 'embedded', '—'][idx % 6],
                    gateway_id: gw.id,
                    gateway_name: gw.name,
                    link_kind: c.key === 'phone' ? 'wireless' : 'wired',
                    health: { state: hstate, score: score, latency_ms: latency, loss_pct: hstate === 'offline' ? 100 : hstate === 'degraded' ? 2 + (idx % 9) : 0, reachable: hstate !== 'offline' },
                    quarantined: quarantine,
                    risk: hstate === 'offline' ? 'high' : hstate === 'degraded' ? 'medium' : 'low',
                    open_ports: (idx * 3) % 9,
                    vuln_count: (idx * 5) % 11,
                    battery: c.key === 'iot' ? 30 + (idx * 7) % 70 : null,
                    first_seen: new Date(Date.now() - (idx * 7.3e6)).toISOString(),
                    last_seen: new Date(Date.now() - (idx % 6) * 60000).toISOString(),
                    is_gateway: false,
                    open_ports: 2 + (idx % 7)
                });
            }
        });
        DEMO_GATEWAYS.forEach(function (g) {
            g.device_count = devices.filter(function (d) { return d.gateway_id === g.id; }).length;
            g.healthy = devices.filter(function (d) { return d.gateway_id === g.id && healthOf(d) === 'healthy'; }).length;
            g.degraded = devices.filter(function (d) { return d.gateway_id === g.id && healthOf(d) === 'degraded'; }).length;
            g.offline = devices.filter(function (d) { return d.gateway_id === g.id && healthOf(d) === 'offline'; }).length;
            g.quarantined = devices.filter(function (d) { return d.gateway_id === g.id && d.quarantined; }).length;
        });
        var incidents = [
            { id: 'incident:demo-1', title: 'Lab uplink saturated', severity: 'high', status: 'open', blast_radius: 14, created_at: new Date(Date.now() - 22 * 60000).toISOString(), gateway_ids: [DEMO_GATEWAYS[1].id], device_keys: devices.filter(function (d) { return d.gateway_id === DEMO_GATEWAYS[1].id && healthOf(d) !== 'healthy'; }).slice(0, 4).map(function (d) { return d.key; }), description: 'Uplink retransmits crossed 12% for four consecutive probe cycles.' },
            { id: 'incident:demo-2', title: 'Camera cluster unreachable', severity: 'high', status: 'open', blast_radius: 9, created_at: new Date(Date.now() - 9 * 60000).toISOString(), gateway_ids: [DEMO_GATEWAYS[2].id], device_keys: devices.filter(function (d) { return d.gateway_id === DEMO_GATEWAYS[2].id && d.category === 'camera' && healthOf(d) === 'offline'; }).map(function (d) { return d.key; }), description: 'Three edge cameras stopped answering ARP after PoE budget alarm.' },
            { id: 'incident:demo-3', title: 'Unknown endpoints quarantined', severity: 'medium', status: 'open', blast_radius: 8, created_at: new Date(Date.now() - 48 * 60000).toISOString(), gateway_ids: [DEMO_GATEWAYS[0].id], device_keys: devices.filter(function (d) { return d.quarantined; }).slice(0, 3).map(function (d) { return d.key; }), description: 'Newly scanned MACs held outside the trusted perimeter until fingerprinting completes.' },
            { id: 'incident:demo-4', title: 'Printer spool retries', severity: 'low', status: 'investigating', created_at: new Date(Date.now() - 2.5 * 3600000).toISOString(), gateway_ids: [DEMO_GATEWAYS[0].id], device_keys: devices.filter(function (d) { return d.category === 'printer'; }).slice(0, 2).map(function (d) { return d.key; }), description: 'Intermittent 631 resets on the floor-2 print VLAN.' }
        ];
        var links = devices.map(function (d) {
            return { id: 'link:' + d.key, source: d.key, target: d.gateway_id, kind: d.link_kind, quality: healthOf(d) === 'offline' ? 'bad' : healthOf(d) === 'degraded' ? 'fair' : 'good' };
        });
        return {
            seq: 1,
            generated_at: new Date().toISOString(),
            collector: 'simulation',
            devices: devices,
            gateways: DEMO_GATEWAYS,
            incidents: incidents,
            links: links,
            clusters: [],
            summary: {
                total: devices.length,
                healthy: devices.filter(function (d) { return healthOf(d) === 'healthy'; }).length,
                degraded: devices.filter(function (d) { return healthOf(d) === 'degraded'; }).length,
                offline: devices.filter(function (d) { return healthOf(d) === 'offline'; }).length,
                quarantined: devices.filter(function (d) { return d.quarantined; }).length,
                unidentified: devices.filter(function (d) { return d.quarantined; }).length,
                active_incidents: incidents.length,
                gateways: DEMO_GATEWAYS.length,
                avg_latency_ms: 41.2
            }
        };
    }

    function demoTick() {
        if (state.mode !== 'demo' || !state.fleet) return;
        var pool = state.devices.filter(function (d) { return !d.is_gateway; });
        if (!pool.length) return;

        // latency drift + occasional health transitions
        pool.forEach(function (d) {
            if (healthOf(d) === 'offline') return;
            var base = d.health.latency_ms == null ? 12 : d.health.latency_ms;
            d.health.latency_ms = Math.max(0.4, base + (Math.random() - 0.5) * 14);
            d.health.score = clamp((d.health.score || 80) + (Math.random() - 0.5) * 4, 8, 99);
        });
        for (var i = 0; i < 2; i++) {
            var d = pool[Math.floor(Math.random() * pool.length)];
            if (!d) continue;
            var roll = Math.random();
            if (roll < 0.10 && healthOf(d) !== 'degraded' && healthOf(d) !== 'offline') {
                d.health.state = 'degraded'; d.health.loss_pct = 3 + Math.random() * 8;
                pushEvent({ type: 'health.degraded', ts: new Date().toISOString(), device: d, detail: 'probe loss climbing on ' + d.ip });
            } else if (roll < 0.16 && healthOf(d) === 'degraded') {
                d.health.state = 'healthy'; d.health.loss_pct = 0;
                pushEvent({ type: 'health.recovered', ts: new Date().toISOString(), device: d, detail: 'latency back under threshold' });
            } else if (roll < 0.20 && !d.quarantined) {
                d.health.state = 'offline'; d.health.latency_ms = null; d.health.reachable = false;
                pushEvent({ type: 'device.lost', ts: new Date().toISOString(), device: d, detail: d.ip + ' stopped answering probes' });
            } else if (roll < 0.23 && healthOf(d) === 'offline') {
                d.health.state = 'healthy'; d.health.latency_ms = 8 + Math.random() * 20; d.health.reachable = true;
                pushEvent({ type: 'health.recovered', ts: new Date().toISOString(), device: d, detail: 'device back on the wire' });
            }
        }

        // roaming between gateways
        if (Math.random() < 0.55) {
            var roam = pool[Math.floor(Math.random() * pool.length)];
            var target = DEMO_GATEWAYS.filter(function (g) { return g.id !== roam.gateway_id; })[Math.floor(Math.random() * 2)];
            if (roam && target && !roam.is_gateway) {
                var fromId = roam.gateway_id, fromName = roam.gateway_name;
                roam.gateway_id = target.id; roam.gateway_name = target.name;
                roam.link_kind = 'wireless';
                roamAll(roam.key, fromId, target.id);
                pushEvent({
                    type: 'device.roamed', ts: new Date().toISOString(), device: roam,
                    from_gateway: fromId, from_gateway_name: fromName,
                    to_gateway: target.id, to_gateway_name: target.name,
                    detail: roam.name + ' reassociated to ' + target.name
                });
            }
        }

        // heartbeats / scan pulses
        for (var p = 0; p < 3; p++) {
            var pd = pool[Math.floor(Math.random() * pool.length)];
            if (pd) pulseAll(pd.key, 'heartbeat');
        }

        var c = counts();
        if (state.fleet.summary) {
            state.fleet.summary.healthy = c.healthy;
            state.fleet.summary.degraded = c.degraded;
            state.fleet.summary.offline = c.offline;
        }
        renderKpis();
        updateAll();
    }

    /* ---------------- public API ---------------- */
    var api = {
        state: state,
        mount: function () {
            if (state.mounted) return;
            state.mounted = true;
            var saved = null;
            try { saved = localStorage.getItem('fleet.mode'); } catch (e) { }
            if (saved === 'demo') {
                setTimeout(function () { api.setMode('demo'); }, 0);
            } else {
                state.mode = 'live';
                connect();
                fetchSnapshot(true);
            }
        },
        onShow: function () {
            state.visible = true;
            api.mount();
            if (state.mode === 'live' && !state.fleet) fetchSnapshot(true);
            if (views.resume) views.resume();
        },
        onHide: function () { state.visible = false; },
        setMode: function (mode) {
            if (mode === state.mode) return;
            state.mode = mode === 'demo' ? 'demo' : 'live';
            try { localStorage.setItem('fleet.mode', state.mode); } catch (e) { }
            document.querySelectorAll('[data-fleet-mode]').forEach(function (b) {
                b.classList.toggle('is-active', b.getAttribute('data-fleet-mode') === state.mode);
            });
            clearInterval(state.demoTimer);
            state.demoTimer = null;
            if (state.es) { state.es.close(); state.es = null; }
            state.events = [];
            state._seeded = false;
            state.selected = null; state.hovered = null;
            state._built = false;
            closeDrawer();
            if (state.mode === 'demo') {
                state.fleet = null;
                var demo = buildDemo();
                applyFleet(demo, 'sim');
                updateConn('sim');
                toast('Simulation · 120 devices, 3 gateways, live roaming');
                state.events = [];
                pushEvent({ type: 'device.discovered', device: demo.devices[0], detail: 'simulation stream attached', ts: new Date().toISOString() });
                connect(); // keep an SSE tap alive so switching back is instant
                state.demoTimer = setInterval(demoTick, 3200);
            } else {
                state.events = [];
                updateConn('connecting');
                connect();
                fetchSnapshot(false);
            }
        },
        refresh: function () {
            if (state.mode === 'demo') {
                var demo = buildDemo();
                state._built = false;
                applyFleet(demo, 'sim');
                toast('Simulation reseeded · 120 devices');
                return;
            }
            fetchSnapshot(false);
        },
        select: select,
        hover: hover,
        clearHover: clearHover,
        clearSelection: clearSelection,
        groupInfo: groupInfo,
        focusTargets: focusTargets,
        clusterKey: clusterKey,
        zoneOf: zoneOf,
        openDrawer: openDrawer,
        closeDrawer: closeDrawer,
        locate: function (key) {
            select(key, { reveal: true, open: true });
            toast('Linked across topology, bullseye and matrix');
        },
        toggleGateway: function (id) {
            state.expandedGateways[id] = !state.expandedGateways[id];
            rebuildTopology();
        },
        toggleCategory: function (cat) {
            state.expandedCategories[cat] = !state.expandedCategories[cat];
            rebuildTopology();
        },
        expandAll: function () {
            state.gates.forEach(function (g) { state.expandedGateways[g.id] = true; });
            Object.keys(state.catByKey).forEach(function (c) { state.expandedCategories[c] = true; });
            rebuildTopology();
            toast('All clusters expanded');
        },
        collapseAll: function () {
            state.gates.forEach(function (g) { state.expandedGateways[g.id] = false; });
            Object.keys(state.catByKey).forEach(function (c) { state.expandedCategories[c] = false; });
            rebuildTopology();
            toast('Clusters collapsed to gateways');
        },
        copyIp: function (ip) {
            if (!ip) return;
            var done = function () { toast('Copied ' + ip); };
            if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(ip).then(done, function () { toast(ip); });
            else toast(ip);
        },
        isVisible: function () {
            var el = $('fleet-view');
            return !!(el && state.visible && !el.hidden && el.style.display !== 'none' && !document.hidden);
        },
        esc: esc,
        timeAgo: timeAgo,
        fmtMs: fmtMs,
        num: num,
        svgEl: svgEl,
        categoryColor: categoryColor,
        healthOf: healthOf,
        toast: toast
    };
    window.FleetOps = api;

    /* One shared animation pump for the views that need a tick. Bullseye runs
       its own loop (it owns drift + collision), so only topology is driven here.
       While the drawer is open the workspace is deliberately frozen: the scrim
       already blurs it, and continuing to repaint 120 nodes behind a backdrop
       filter is what made cursor movement feel sluggish. */
    function frame(now) {
        if (api.isVisible() && !document.body.classList.contains('drawer-open') && views.tickTopology) {
            views.tickTopology(now);
        }
        requestAnimationFrame(frame);
    }
    requestAnimationFrame(frame);

    /* global shortcuts */
    document.addEventListener('keydown', function (ev) {
        if (!api.isVisible()) return;
        if (ev.key === 'Escape') { api.closeDrawer(); api.clearHover(); }
        if (ev.key === '/' && document.activeElement && /INPUT|TEXTAREA/.test(document.activeElement.tagName)) return;
    });
})();
