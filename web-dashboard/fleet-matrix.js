/* ==========================================================================
   Diagram 3 — interactive telemetry matrix (hex grid)
   One cell per device, grouped into categorical blocks. No links, no labels,
   just colour, pulse and a hover/click path into the diagnostic drawer.
   ========================================================================== */
(function () {
    'use strict';
    var O = window.FleetOps;
    var V = window.FleetViews = window.FleetViews || {};
    if (!O) return;
    var S = O.state;

    var host, svg, world, toolbar;
    var built = false;
    var cells = {};        // key -> {poly, g, x, y, ref}
    var mode = 'type';     // 'type' | 'zone'
    var W = 0, H = 0, S0 = 9, RAIL = 104;

    function dims() {
        var r = host.getBoundingClientRect();
        W = Math.max(520, r.width);
        H = Math.max(380, r.height);
        if (svg) svg.setAttribute('viewBox', '0 0 ' + W + ' ' + H);
    }

    function grouping() {
        var groups = {};
        S.devices.forEach(function (d) {
            if (d.is_gateway) return;
            var k, label;
            if (mode === 'zone') {
                k = O.zoneOf(d.category);
                label = k;
            } else {
                k = d.category;
                label = d.category_label || d.category;
            }
            if (!groups[k]) groups[k] = { key: k, label: label, items: [] };
            groups[k].items.push(d);
        });
        var arr = Object.keys(groups).map(function (k) { return groups[k]; });
        arr.forEach(function (g) {
            g.items.sort(function (a, b) {
                var ha = O.healthOf(a), hb = O.healthOf(b);
                var order = { offline: 0, degraded: 1, unidentified: 2, healthy: 3 };
                return (order[ha] - order[hb]) || String(a.name || '').localeCompare(String(b.name || ''));
            });
        });
        arr.sort(function (a, b) {
            if (mode === 'zone') return a.label.localeCompare(b.label);
            return b.items.length - a.items.length || a.label.localeCompare(b.label);
        });
        return arr;
    }

    function layout(groups, s) {
        var cw = Math.sqrt(3) * s, rh = 1.5 * s;
        var avail = W - RAIL - 18;
        var maxCols = Math.max(4, Math.floor(avail / cw));
        var y = 30;
        groups.forEach(function (g) {
            g.rows = Math.ceil(g.items.length / maxCols);
            g.y = y;
            g.cw = cw; g.rh = rh; g.cols = Math.min(maxCols, Math.max(1, g.items.length));
            y += Math.max(38, g.rows * rh + s * 2 + 12);
        });
        return y;
    }

    function build() {
        host = document.getElementById('fleet-matrix');
        if (!host || !S.fleet) return;
        dims();
        var oldSvg = document.getElementById('fleet-matrix-svg');
        if (oldSvg) oldSvg.remove();
        if (toolbar && toolbar.parentNode) toolbar.parentNode.removeChild(toolbar);
        cells = {};
        var groups = grouping();
        var s = 10.5, total = 0;
        while (s >= 5.2) {
            total = layout(groups, s);
            if (total <= H - 8) break;
            s -= 0.4;
        }
        S0 = s;
        if (total < H - 40) {
            // Sparse zone views leave the canvas mostly empty; center the bands.
            var dy = Math.round((H - total) / 2);
            groups.forEach(function (g) { g.y += dy; });
            total += dy;
        }

        toolbar = document.createElement('div');
        toolbar.className = 'mx-toolbar';
        toolbar.innerHTML = '<span class="mx-title">Telemetry matrix</span>' +
            '<span class="mx-sub">' + S.devices.filter(function (d) { return !d.is_gateway; }).length + ' cells · no links</span>' +
            '<span class="mx-spacer"></span>' +
            '<button type="button" class="mx-mode' + (mode === 'type' ? ' is-on' : '') + '" data-mode="type">By type</button>' +
            '<button type="button" class="mx-mode' + (mode === 'zone' ? ' is-on' : '') + '" data-mode="zone">By zone</button>';
        host.appendChild(toolbar);
        toolbar.querySelectorAll('.mx-mode').forEach(function (b) {
            b.addEventListener('click', function () {
                var m = b.getAttribute('data-mode');
                if (m === mode) return;
                mode = m;
                V.buildMatrix();
            });
        });

        svg = O.svgEl('svg', { id: 'fleet-matrix-svg', viewBox: '0 0 ' + W + ' ' + H, role: 'img', 'aria-label': 'Hexagonal telemetry matrix grouped by ' + mode });
        world = O.svgEl('g');
        svg.appendChild(world);

        groups.forEach(function (g) {
            section(g);
        });

        legend(total > 0 ? total : 0);
        host.appendChild(svg);
        svg.addEventListener('click', function (ev) {
            if (ev.target.closest('.mx-cell,.mx-section')) return;
            O.clearSelection();
        });
        built = true;
        highlight();
    }

    function section(g) {
        var cw = g.cw, rh = g.rh;
        var counts = { healthy: 0, degraded: 0, offline: 0, unidentified: 0 };
        g.items.forEach(function (d) {
            var h = O.healthOf(d); counts[h] = (counts[h] || 0) + 1;
        });
        var gkey = mode === 'zone' ? 'zone:' + g.key : O.clusterKey('*', g.key);
        var head = O.svgEl('g', {
            class: 'mx-section', 'data-key': gkey, tabindex: '0', role: 'button',
            'aria-label': g.label + ' group, ' + g.items.length + ' devices. Click to pin, click again for diagnostics.'
        });
        head.addEventListener('click', function (ev) { ev.stopPropagation(); O.select(gkey); });
        head.addEventListener('mouseenter', function () { O.hover(gkey); });
        head.addEventListener('mouseleave', function () { O.clearHover(); });
        head.addEventListener('keydown', function (ev) {
            if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); O.select(gkey); }
        });
        var t = O.svgEl('text', { class: 'mx-lab', x: 4, y: g.y + 11 });
        t.textContent = g.label;
        head.appendChild(t);
        var sub = O.svgEl('text', { class: 'mx-count', x: 4, y: g.y + 23 });
        sub.textContent = g.items.length + ' devices';
        head.appendChild(sub);
        // health mini-bar
        var total = Math.max(1, g.items.length), bx = 4, bw = 88, by = g.y + 30;
        ['healthy', 'degraded', 'unidentified', 'offline'].forEach(function (k) {
            if (!counts[k]) return;
            var w = Math.max(1.5, counts[k] / total * bw);
            head.appendChild(O.svgEl('rect', { class: 'mx-hb is-' + k, x: bx, y: by, width: w, height: 2.6, rx: 1.3 }));
            bx += w + 1;
        });
        world.appendChild(head);

        var startX = RAIL + 6;
        g.items.forEach(function (d, i) {
            var col = i % g.cols, row = Math.floor(i / g.cols);
            var x = startX + col * cw + (row % 2 ? cw / 2 : 0);
            var y = g.y + 8 + row * rh + S0;
            cell(d, x, y, S0);
        });
    }

    function cell(d, x, y, s) {
        var hs = O.healthOf(d);
        var q = !!d.quarantined;
        var grp = O.svgEl('g', {
            class: 'mx-cell is-' + (q ? 'quarantined' : hs) + (d.key === S.selected ? ' is-selected' : ''),
            transform: 'translate(' + x.toFixed(1) + ',' + y.toFixed(1) + ')',
            'data-key': d.key, tabindex: '0', role: 'button',
            'aria-label': (d.name || d.ip) + ', ' + (q ? 'unidentified, quarantined' : hs) + '. Open diagnostics.'
        });
        // pointy-top hexagon
        var pts = [];
        for (var i = 0; i < 6; i++) {
            var a = Math.PI / 180 * (60 * i - 30);
            pts.push((Math.cos(a) * s).toFixed(2) + ',' + (Math.sin(a) * s).toFixed(2));
        }
        grp.innerHTML = '<polygon class="mx-hex" points="' + pts.join(' ') + '"></polygon>' +
            '<polygon class="mx-hex-ring" points="' + pts.join(' ') + '"></polygon>' +
            '<circle class="mx-dot" r="' + (s * 0.22).toFixed(1) + '"></circle>';
        grp.addEventListener('click', function (ev) { ev.stopPropagation(); O.select(d.key); });
        grp.addEventListener('mouseenter', function () { O.hover(d.key); });
        grp.addEventListener('mouseleave', function () { O.clearHover(); });
        grp.addEventListener('keydown', function (ev) {
            if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); O.select(d.key); }
        });
        world.appendChild(grp);
        cells[d.key] = { el: grp, ref: d, x: x, y: y, s: s };
    }

    function legend() {
        var items = [['healthy', 'Healthy'], ['degraded', 'Degraded'], ['offline', 'Offline'], ['unidentified', 'Unidentified']];
        var g = O.svgEl('g', { class: 'mx-legend', transform: 'translate(' + (W - 330) + ',12)' });
        var x = 0;
        items.forEach(function (it) {
            var dot = O.svgEl('circle', { class: 'mx-lg is-' + it[0], cx: x + 4, cy: 4, r: 4 });
            g.appendChild(dot);
            var tx = O.svgEl('text', { x: x + 12, y: 8 });
            tx.textContent = it[1];
            g.appendChild(tx);
            x += 22 + it[1].length * 6.4;
        });
        world.appendChild(g);
    }

    function sectionHit(grp, gk) {
        if (!grp) return false;
        if (gk.indexOf('zone:') === 0) return grp.kind === 'zone' && grp.zone === gk.slice(5);
        if (gk.indexOf('cluster:') !== 0) return false;
        var body = gk.slice(8), sep = body.indexOf('|');
        if (sep < 0) return false;
        return grp.kind === 'category' && grp.category === body.slice(sep + 1);
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
                var c = cells[k];
                return !!c && c.ref.category === t.dev.category;
            }
            return false;
        }
        Object.keys(cells).forEach(function (k) {
            var c = cells[k];
            if (!c.el) return;
            var isFocus = targets.some(function (t) { return hit(t, k); });
            var sameCtx = targets.some(function (t) {
                return !t.grp && t.dev && !t.dev.is_gateway && c.ref.category === t.dev.category;
            });
            c.el.classList.toggle('is-selected', S.selected === k || member(selGrp, k));
            c.el.classList.toggle('is-hovered', S.hovered === k || member(hovGrp, k));
            c.el.classList.toggle('is-same', sameCtx);
            c.el.classList.toggle('is-dim', targets.length > 0 && !isFocus);
        });
        if (svg) {
            svg.querySelectorAll('.mx-section').forEach(function (el) {
                var gk = el.getAttribute('data-key');
                var isFocusSection = targets.some(function (t) {
                    return t.key === gk || !!(t.grp && sectionHit(t.grp, gk));
                });
                el.classList.toggle('is-selected', S.selected === gk || !!(selGrp && sectionHit(selGrp, gk)));
                el.classList.toggle('is-hovered', S.hovered === gk || !!(hovGrp && sectionHit(hovGrp, gk)));
                el.classList.toggle('is-dim', groupTargets.length > 0 && !isFocusSection);
            });
        }
    }

    function focus(key) {
        var c = cells[key];
        if (!c || !c.el) return;
        c.el.classList.add('is-selected');
        var ring = O.svgEl('polygon', {
            class: 'mx-focus', points: c.el.querySelector('.mx-hex').getAttribute('points'),
            transform: 'translate(' + c.x + ',' + c.y + ')'
        });
        world.appendChild(ring);
        var t0 = performance.now();
        (function grow() {
            var t = (performance.now() - t0) / 700;
            if (t >= 1 || !ring.parentNode) { ring.remove(); return; }
            ring.setAttribute('transform', 'translate(' + c.x + ',' + c.y + ') scale(' + (1 + t * 1.4) + ')');
            ring.style.opacity = String(0.6 * (1 - t));
            requestAnimationFrame(grow);
        })();
    }

    V.buildMatrix = function () { built = false; build(); };
    V.updateMatrix = function () { if (built) highlight(); };
    V.tickMatrix = function () { };
    V.highlightMatrix = highlight;
    V.focusMatrix = focus;
    V.pulseMatrix = function (key) {
        var c = cells[key];
        if (!c || !c.el) return;
        var p = c.el.querySelector('.mx-hex-ring');
        if (!p) return;
        p.classList.remove('is-on');
        void p.getBoundingClientRect();
        p.classList.add('is-on');
        setTimeout(function () { p.classList.remove('is-on'); }, 720);
    };
    V.roamMatrix = function () { };
})();
