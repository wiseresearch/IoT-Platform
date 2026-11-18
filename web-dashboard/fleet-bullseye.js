/* ==========================================================================
   Diagram 2 — concentric health & latency bullseye
   Centre = network core, radius = responsiveness, wedges = categories.
   Nodes drift continuously and repel each other so labels never collide.
   ========================================================================== */
(function () {
    'use strict';
    var O = window.FleetOps;
    var V = window.FleetViews = window.FleetViews || {};
    if (!O) return;
    var S = O.state;

    var host, svg, world, layerWedge, layerRings, layerNodes, layerLabels;
    var W = 0, H = 0, cx = 0, cy = 0, R = 0;
    var built = false;
    var items = {};   // key -> {a, r, x, y, tx, ty, ref, el, ...}
    var categories = [];
    var geom = null;

    function dims() {
        var rect = host.getBoundingClientRect();
        W = Math.max(480, rect.width);
        H = Math.max(420, rect.height);
        cx = W / 2;
        cy = H / 2 + 4;
        R = Math.max(150, Math.min(W, H) * 0.40);
        if (svg) svg.setAttribute('viewBox', '0 0 ' + W + ' ' + H);
    }

    function norm(d) {
        if (O.healthOf(d) === 'offline') return 0.97;
        if (d.quarantined) return 0.9;
        var h = d.health || {};
        var lat = h.latency_ms != null ? Number(h.latency_ms) : 40;
        var loss = h.loss_pct != null ? Number(h.loss_pct) : 0;
        var score = h.score != null ? Number(h.score) : 92;
        var v = (Math.min(320, Math.max(5, lat)) - 5) / 315 * 0.66 +
            Math.min(25, Math.max(0, loss)) / 25 * 0.2 +
            (100 - Math.min(100, Math.max(0, score))) / 100 * 0.14;
        return Math.max(0.04, Math.min(1, v));
    }

    function activeCategories() {
        var seen = {};
        S.devices.forEach(function (d) { if (!d.is_gateway) seen[d.category] = true; });
        var keys = Object.keys(seen);
        var preferred = ['camera', 'sensor', 'thermostat', 'light', 'lock', 'speaker', 'plug', 'hub', 'router', 'printer', 'tv', 'nas', 'unknown'];
        keys.sort(function (a, b) {
            var ia = preferred.indexOf(a), ib = preferred.indexOf(b);
            if (ia < 0) ia = 99; if (ib < 0) ib = 99;
            return ia - ib || a.localeCompare(b);
        });
        return keys.map(function (k) { return S.catByKey[k] || { key: k, label: k }; });
    }

    /* Category wedges are sized by population (with a floor) so a 30-node
       category gets breathing room while six-node categories stay readable. */
    function layoutWedges() {
        var total = 0;
        categories.forEach(function (cat) {
            cat.count = S.devices.filter(function (d) { return d.category === cat.key && !d.is_gateway; }).length;
            total += cat.count;
        });
        total = Math.max(1, total);
        var n = Math.max(1, categories.length);
        var minSpan = Math.min(0.26, (Math.PI * 2 / n) * 0.5);
        var free = Math.max(0, Math.PI * 2 - minSpan * n);
        var cursor = -Math.PI / 2;
        categories.forEach(function (cat) {
            var span = minSpan + free * (cat.count / total);
            cat.a0 = cursor;
            cat.a1 = cursor + span;
            cat.gap = Math.min(0.02, span * 0.045);
            cursor += span;
        });
        return { gap: 0.018 };
    }

    function build() {
        host = document.getElementById('fleet-bullseye');
        if (!host || !S.fleet) return;
        dims();
        var old = document.getElementById('fleet-bullseye-svg');
        if (old) old.remove();
        items = {};
        categories = activeCategories();

        svg = O.svgEl('svg', { id: 'fleet-bullseye-svg', class: S.devices.length > 30 ? 'is-dense' : '', viewBox: '0 0 ' + W + ' ' + H, role: 'img', 'aria-label': 'Concentric health and latency bullseye' });
        var defs = O.svgEl('defs');
        defs.innerHTML = '<radialGradient id="be-core" cx="50%" cy="50%" r="50%"><stop offset="0%" stop-color="var(--fl-teal)" stop-opacity=".22"/><stop offset="100%" stop-color="var(--fl-teal)" stop-opacity="0"/></radialGradient>' +
            '<filter id="be-soft" x="-40%" y="-40%" width="180%" height="180%"><feGaussianBlur stdDeviation="2.4" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>';
        svg.appendChild(defs);
        world = O.svgEl('g');
        svg.appendChild(world);

        world.appendChild(O.svgEl('circle', { cx: cx, cy: cy, r: R * 1.02, fill: 'url(#be-core)' }));
        layerWedge = O.svgEl('g', { class: 'be-wedges' });
        layerRings = O.svgEl('g', { class: 'be-rings' });
        layerNodes = O.svgEl('g', { class: 'be-nodes' });
        layerLabels = O.svgEl('g', { class: 'be-labels' });
        world.appendChild(layerWedge);
        world.appendChild(layerRings);
        world.appendChild(layerNodes);
        world.appendChild(layerLabels);

        geom = layoutWedges();

        // zones
        [
            { r: R * 0.38, label: 'HEALTHY', cls: '' },
            { r: R * 0.70, label: 'DEGRADED', cls: 'is-warn' },
            { r: R, label: 'CRITICAL', cls: 'is-bad' }
        ].forEach(function (z) {
            var c = O.svgEl('circle', { class: 'be-zone ' + z.cls, cx: cx, cy: cy, r: z.r });
            layerRings.appendChild(c);
        });
        // radial spokes + wedge labels
        categories.forEach(function (cat, i) {
            var a0 = cat.a0 + cat.gap;
            var a1 = cat.a1 - cat.gap;
            var p = O.svgEl('path', {
                class: 'be-wedge-line',
                d: 'M' + (cx + Math.cos(a0) * R * 0.44) + ',' + (cy + Math.sin(a0) * R * 0.44) +
                    ' L' + (cx + Math.cos(a0) * R * 1.06) + ',' + (cy + Math.sin(a0) * R * 1.06) +
                    ' M' + (cx + Math.cos(a1) * R * 0.44) + ',' + (cy + Math.sin(a1) * R * 0.44) +
                    ' L' + (cx + Math.cos(a1) * R * 1.06) + ',' + (cy + Math.sin(a1) * R * 1.06)
            });
            layerWedge.appendChild(p);
            var mid = (a0 + a1) / 2;
            var lx = cx + Math.cos(mid) * (R * 1.12);
            var ly = cy + Math.sin(mid) * (R * 1.12);
            var anchor = Math.cos(mid) > 0.25 ? 'start' : Math.cos(mid) < -0.25 ? 'end' : 'middle';
            var wkey = O.clusterKey('*', cat.key);
            var wg = O.svgEl('g', {
                class: 'be-wedge-group', 'data-key': wkey, tabindex: '0', role: 'button',
                'aria-label': cat.label + ' category group. Click to pin, click again for diagnostics.'
            });
            var lbl = O.svgEl('text', { class: 'be-wedge-label', x: lx, y: ly + 3, 'text-anchor': anchor });
            lbl.textContent = cat.label;
            wg.appendChild(lbl);
            var cnt = S.devices.filter(function (d) { return d.category === cat.key && !d.is_gateway; }).length;
            var sub = O.svgEl('text', { class: 'be-wedge-count', x: lx, y: ly + 14, 'text-anchor': anchor });
            sub.textContent = cnt + ' nodes';
            wg.appendChild(sub);
            wg.addEventListener('click', function (ev) { ev.stopPropagation(); O.select(wkey); });
            wg.addEventListener('mouseenter', function () { O.hover(wkey); });
            wg.addEventListener('mouseleave', function () { O.clearHover(); });
            wg.addEventListener('keydown', function (ev) {
                if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); O.select(wkey); }
            });
            layerLabels.appendChild(wg);
        });

        // core
        var core = O.svgEl('g', { class: 'be-core', transform: 'translate(' + cx + ',' + cy + ')', tabindex: '0', role: 'button', 'aria-label': 'Network core' });
        core.innerHTML = '<circle class="core-halo" r="' + (R * 0.22 + 8) + '"></circle>' +
            '<circle class="core-plate" r="' + (R * 0.16 + 22) + '"></circle>' +
            '<circle class="core-ring" r="' + (R * 0.16 + 15) + '"></circle>' +
            '<path class="core-icon" d="M-9 1h18M0 -8v18M-6 8h12" stroke-width="1.5" stroke-linecap="round" fill="none"></path>' +
            '<text class="core-label" x="0" y="-21" text-anchor="middle">NETWORK CORE</text>' +
            '<text class="core-sub" x="0" y="30" text-anchor="middle">' + O.esc(S.gates.length + ' GW · ' + S.devices.length + ' NODES') + '</text>';
        layerLabels.appendChild(core);
        core.addEventListener('click', function (ev) {
            ev.stopPropagation();
            if (S.gates[0]) O.select(S.gates[0].id);
        });

        // health-band legend (kept outside the radial field so no node or wedge label can collide)
        if (cx - R > 170) {
            var lg = O.svgEl('g', { class: 'be-legend', transform: 'translate(18,' + (cy - 46) + ')' });
            lg.innerHTML = '<rect class="be-legend-plate" x="0" y="0" width="146" height="92" rx="11"></rect>' +
                '<text class="be-legend-title" x="12" y="18">HEALTH ZONES</text>' +
                '<circle class="be-legend-dot" cx="16" cy="37" r="5.5"></circle>' +
                '<text class="be-legend-label" x="30" y="40">Healthy</text>' +
                '<text class="be-legend-range" x="134" y="40" text-anchor="end">0–38%</text>' +
                '<circle class="be-legend-dot is-warn" cx="16" cy="58" r="5.5"></circle>' +
                '<text class="be-legend-label" x="30" y="61">Degraded</text>' +
                '<text class="be-legend-range" x="134" y="61" text-anchor="end">38–70%</text>' +
                '<circle class="be-legend-dot is-bad" cx="16" cy="79" r="5.5"></circle>' +
                '<text class="be-legend-label" x="30" y="82">Critical</text>' +
                '<text class="be-legend-range" x="134" y="82" text-anchor="end">70–100%</text>';
            layerLabels.appendChild(lg);
        }

        // nodes grouped by category -> ordered by angle inside wedge
        var byCat = {};
        S.devices.forEach(function (d) {
            if (d.is_gateway) return;
            (byCat[d.category] = byCat[d.category] || []).push(d);
        });
        categories.forEach(function (cat, i) {
            var list = (byCat[cat.key] || []).slice().sort(function (a, b) {
                var sa = String(a.name || a.ip || a.key), sb = String(b.name || b.ip || b.key);
                return sa.localeCompare(sb);
            });
            var a0 = cat.a0 + cat.gap * 2;
            var a1 = cat.a1 - cat.gap * 2;
            list.forEach(function (d, j) {
                var f = (j + 0.5) / Math.max(1, list.length);
                var baseA = a0 + (a1 - a0) * f;
                var r0 = norm(d);
                var rr = R * (0.46 + r0 * 0.52);
                var it = {
                    ref: d, a: baseA, baseA: baseA, r: rr, tx: cx + Math.cos(baseA) * rr, ty: cy + Math.sin(baseA) * rr,
                    x: cx + Math.cos(baseA) * rr, y: cy + Math.sin(baseA) * rr, spin: 0, el: null, idx: j, index: j, cat: cat.key
                };
                items[d.key] = it;
                var grp = nodeEl(d);
                layerNodes.appendChild(grp);
                it.el = grp;
                it.g = grp;
            });
        });

        var q = S.devices.filter(function (d) { return d.quarantined; }).length;
        var badge = O.svgEl('text', { class: 'be-quarantine-note', x: 12, y: H - 12 });
        badge.textContent = q ? q + ' quarantined nodes sit on the outer critical band until fingerprinting completes' : '';
        layerLabels.appendChild(badge);

        host.appendChild(svg);
        bindEvents();
        built = true;
        if (!loopStarted) {
            loopStarted = true;
            requestAnimationFrame(loop);
        }
    }

    var loopStarted = false;
    function loop(now) {
        if (!built) { requestAnimationFrame(loop); return; }
        if (O.isVisible() && !document.body.classList.contains('drawer-open')) drift(now);
        requestAnimationFrame(loop);
    }

    function nodeEl(d) {
        var hs = O.healthOf(d);
        var q = !!d.quarantined;
        var grp = O.svgEl('g', {
            class: 'be-node is-' + (q ? 'quarantined' : hs), 'data-key': d.key,
            tabindex: '0', role: 'button',
            'aria-label': (d.name || d.ip) + ', ' + hs + ', ' + (d.health && d.health.latency_ms != null ? Math.round(d.health.latency_ms) + ' milliseconds' : 'latency unknown')
        });
        var r = q ? 5.4 : 6.4;
        grp.innerHTML = '<circle class="be-hit" r="16" fill="transparent"></circle>' +
            '<circle class="be-pulse" r="' + (r + 5) + '"></circle>' +
            '<circle class="be-dot" r="' + r + '"></circle>' +
            '<circle class="be-qring" r="' + (r + 3) + '"></circle>' +
            '<text class="be-node-label" x="0" y="' + (-r - 8) + '" text-anchor="middle">' + O.esc(d.name || d.ip || '') + '</text>';
        grp.addEventListener('click', function (ev) { ev.stopPropagation(); O.select(d.key); });
        grp.addEventListener('mouseenter', function () { O.hover(d.key); });
        grp.addEventListener('mouseleave', function () { O.clearHover(); });
        grp.addEventListener('keydown', function (ev) { if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); O.select(d.key); } });
        return grp;
    }

    function updatePositions() {
        Object.keys(items).forEach(function (k) {
            var it = items[k];
            if (it.el) it.el.setAttribute('transform', 'translate(' + it.x.toFixed(1) + ',' + it.y.toFixed(1) + ')');
        });
    }

    function drift(now) {
        if (!built) return;
        var keys = Object.keys(items);
        keys.forEach(function (k) {
            var it = items[k];
            var d = it.ref;
            var r0 = norm(d);
            var breathe = Math.sin(now / 2600 + it.index * 1.7) * 0.012;
            var targetR = R * (0.46 + Math.min(0.98, Math.max(0.02, r0 + breathe)) * 0.52);
            var targetA = it.baseA + Math.sin(now / 5200 + it.index) * 0.006;
            it.tx = cx + Math.cos(targetA) * targetR;
            it.ty = cy + Math.sin(targetA) * targetR;
            it.x += (it.tx - it.x) * 0.06;
            it.y += (it.ty - it.y) * 0.06;
        });
        // collision resolution: angular + radial nudge inside each wedge
        for (var i = 0; i < keys.length; i++) {
            var a = items[keys[i]];
            for (var j = i + 1; j < keys.length; j++) {
                var b = items[keys[j]];
                if (a.cat !== b.cat && Math.abs(a.a - b.a) > 0.5) continue;
                var dx = b.x - a.x, dy = b.y - a.y;
                var dist = Math.sqrt(dx * dx + dy * dy) || 0.001;
                var min = 17;
                if (dist < min) {
                    var push = (min - dist) * 0.5;
                    var ux = dx / dist, uy = dy / dist;
                    a.x -= ux * push; a.y -= uy * push;
                    b.x += ux * push; b.y += uy * push;
                }
            }
        }
        updatePositions();
    }

    function wedgeHit(grp, gk) {
        if (!grp || gk.indexOf('cluster:') !== 0) return false;
        var body = gk.slice(8), sep = body.indexOf('|');
        if (sep < 0) return false;
        var cat = body.slice(sep + 1);
        if (grp.kind === 'category') return grp.category === cat;
        if (grp.kind === 'zone') return O.zoneOf(cat) === grp.zone;
        return false;
    }

    function highlight(key) {
        if (!built) return;
        var targets = O.focusTargets();
        if (!targets.length && key) targets = [{ key: key, grp: O.groupInfo(key), dev: S.devByKey[key] || null }];
        var selGrp = S.selected ? O.groupInfo(S.selected) : null;
        var hovGrp = S.hovered ? O.groupInfo(S.hovered) : null;
        var groupTargets = targets.filter(function (t) { return !!t.grp; });
        function member(grp, k) { return !!(grp && grp.memberKeys && grp.memberKeys[k]); }
        function hit(t, k) {
            if (t.key === k || member(t.grp, k)) return true;
            if (!t.grp && t.dev && !t.dev.is_gateway) {
                var it = items[k];
                return !!it && it.ref.category === t.dev.category;
            }
            return false;
        }
        Object.keys(items).forEach(function (k) {
            var it = items[k];
            if (!it.el) return;
            var isFocus = targets.some(function (t) { return hit(t, k); });
            it.el.classList.toggle('is-selected', S.selected === k || member(selGrp, k));
            it.el.classList.toggle('is-hovered', S.hovered === k || member(hovGrp, k));
            it.el.classList.toggle('is-dim', targets.length > 0 && !isFocus);
        });
        var core = svg && svg.querySelector('.be-core');
        if (core) core.classList.toggle('is-hot', targets.some(function (t) {
            return !!(t.dev && t.dev.is_gateway) || !!(t.grp && t.grp.kind === 'gateway');
        }));
        if (svg) {
            svg.querySelectorAll('.be-wedge-group').forEach(function (el) {
                var gk = el.getAttribute('data-key');
                var isFocusWedge = targets.some(function (t) {
                    return t.key === gk || !!(t.grp && wedgeHit(t.grp, gk));
                });
                el.classList.toggle('is-selected', S.selected === gk || !!(selGrp && wedgeHit(selGrp, gk)));
                el.classList.toggle('is-hovered', S.hovered === gk || !!(hovGrp && wedgeHit(hovGrp, gk)));
                el.classList.toggle('is-dim', groupTargets.length > 0 && !isFocusWedge);
            });
        }
    }

    function focus(key) {
        var it = items[key];
        if (!it || !it.el) return;
        it.el.classList.add('is-selected');
        var ring = O.svgEl('circle', { class: 'be-focus-ring', cx: it.x, cy: it.y, r: 6 });
        layerNodes.appendChild(ring);
        var t0 = performance.now();
        (function grow() {
            var t = (performance.now() - t0) / 900;
            if (t >= 1 || !ring.parentNode) { ring.remove(); return; }
            ring.setAttribute('r', String(8 + t * 44));
            ring.style.opacity = String(0.55 * (1 - t));
            requestAnimationFrame(grow);
        })();
    }

    function bindEvents() {
        svg.addEventListener('click', function (ev) {
            if (ev.target.closest('.be-node,.be-core,.be-wedge-group')) return;
            O.clearSelection();
        });
    }

    V.buildBullseye = function () {
        host = document.getElementById('fleet-bullseye');
        if (!host) return;
        built = false;
        build();
        updatePositions();
        highlight();
    };
    V.updateBullseye = function () { if (built) { highlight(); } };
    V.tickBullseye = function (now) { if (O.isVisible() && built) drift(now); };
    V.highlightBullseye = highlight;
    V.focusBullseye = focus;
    V.pulseBullseye = function (key) {
        var it = items[key];
        if (!it || !it.el) return;
        var p = it.el.querySelector('.be-pulse');
        if (!p) return;
        p.classList.remove('is-on');
        void p.getBoundingClientRect();
        p.classList.add('is-on');
        setTimeout(function () { p.classList.remove('is-on'); }, 850);
    };
    V.roamBullseye = function () { };
})();
