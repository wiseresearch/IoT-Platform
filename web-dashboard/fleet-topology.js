/* ==========================================================================
   Diagram 1 — clustered force-directed topology
   Collapsible gateway > category clusters, roaming arcs, blast rings,
   quarantine perimeter and linked cross-view selection.
   ========================================================================== */
(function () {
    'use strict';
    var O = window.FleetOps;
    var V = window.FleetViews = window.FleetViews || {};
    if (!O) return;
    var S = O.state;

    var host, svg, world, layerLinks, layerRoam, layerRings, layerCats, layerNodes, layerLabels;
    var W = 0, H = 0;
    var nodes = {};          // key -> topo node {x,y,vx,vy,tx,ty,ref}
    var hubs = {};           // gateway id -> {x,y,ref,el}
    var cats = {};           // cat key -> [{x,y,el,ref,gw}]
    var roamAnims = [];
    var built = false;
    var view = { k: 1, x: 0, y: 0 };
    var dragging = false, moved = false, dragStart = null;
    var lastKey = null;
    var labelsAlways = false;

    function sclass(d) {
        return 'is-' + (d.quarantined ? 'quarantined' : O.healthOf(d));
    }

    function dims() {
        var r = host.getBoundingClientRect();
        W = Math.max(520, r.width);
        H = Math.max(420, r.height);
        if (svg) { svg.setAttribute('viewBox', '0 0 ' + W + ' ' + H); }
    }

    function catDims(label, count) {
        // 5.8px/char at 9px label type + count column, gap, and chevron gutter.
        var w = Math.max(66, Math.min(168, Math.round(String(label).length * 5.8 + 44 + String(count).length * 7)));
        return { w: w, h: 28 };
    }

    function gatewayPositions() {
        var gws = S.gates;
        var pos = {};
        if (!gws.length) return pos;
        var cx = W / 2, cy = H / 2 + 6;
        if (gws.length === 1) { pos[gws[0].id] = { x: cx, y: cy }; return pos; }
        var rx = Math.min(W * 0.27, 330), ry = Math.min(H * 0.26, 205);
        gws.forEach(function (g, i) {
            var a = -Math.PI / 2 + (i * Math.PI * 2 / gws.length);
            pos[g.id] = { x: cx + Math.cos(a) * rx, y: cy + Math.sin(a) * ry };
        });
        return pos;
    }

    function catSlot(i, n, hub) {
        var a = -Math.PI / 2 + (i * Math.PI * 2 / Math.max(1, n));
        var rx = 142, ry = 112;
        return { x: hub.x + Math.cos(a) * rx, y: hub.y + Math.sin(a) * ry, a: a };
    }

    /* Category pills start on an orbit, then repel each other and their parent
       hub so dense fleets never render overlapping group labels. */
    function settleCatPills() {
        var list = [];
        Object.keys(cats).forEach(function (ck) {
            cats[ck].forEach(function (rec) {
                list.push({ rec: rec, x: rec.x, y: rec.y, w: rec.w, h: 28 });
            });
        });
        if (!list.length) return;
        var pad = 6;
        for (var iter = 0; iter < 90; iter++) {
            var moved = 0;
            for (var i = 0; i < list.length; i++) {
                for (var j = i + 1; j < list.length; j++) {
                    var a = list[i], b = list[j];
                    var dx = b.x - a.x, dy = b.y - a.y;
                    var ox = (a.w + b.w) / 2 + pad - Math.abs(dx);
                    var oy = (a.h + b.h) / 2 + pad - Math.abs(dy);
                    if (ox <= 0 || oy <= 0) continue;
                    if (Math.abs(dx) < 0.01) dx = (i % 2 ? 1 : -1);
                    if (Math.abs(dy) < 0.01) dy = (i % 2 ? -1 : 1);
                    if (ox < oy) {
                        var sx = dx >= 0 ? 1 : -1;
                        a.x -= sx * ox / 2; b.x += sx * ox / 2;
                    } else {
                        var sy = dy >= 0 ? 1 : -1;
                        a.y -= sy * oy / 2; b.y += sy * oy / 2;
                    }
                    moved++;
                }
            }
            list.forEach(function (p) {
                var hub = hubs[p.rec.gw];
                if (hub) {
                    var hx = p.x - hub.x, hy = p.y - (hub.y + 22);
                    var ox = (p.w + 136) / 2 - Math.abs(hx);
                    var oy = (p.h + 96) / 2 - Math.abs(hy);
                    if (ox > 0 && oy > 0) {
                        if (ox < oy) p.x += (hx >= 0 ? 1 : -1) * (ox + 1);
                        else p.y += (hy >= 0 ? 1 : -1) * (oy + 1);
                        moved++;
                    }
                }
                p.x = Math.max(p.w / 2 + 8, Math.min(W - p.w / 2 - 8, p.x));
                p.y = Math.max(p.h / 2 + 8, Math.min(H - p.h / 2 - 8, p.y));
            });
            if (!moved) break;
        }
        list.forEach(function (p) {
            p.rec.x = p.x; p.rec.y = p.y;
            p.rec.el.setAttribute('transform', 'translate(' + p.x + ',' + p.y + ')');
        });
    }

    /* ---------------- build ---------------- */
    function build() {
        host = document.getElementById('fleet-topo');
        if (!host || !S.fleet) return;
        dims();
        var old = document.getElementById('fleet-topo-svg');
        if (old) old.remove();

        svg = O.svgEl('svg', { id: 'fleet-topo-svg', class: S.devices.length > 30 ? 'is-dense' : '', viewBox: '0 0 ' + W + ' ' + H, role: 'img', 'aria-label': 'Clustered fleet topology' });
        var defs = O.svgEl('defs');
        defs.innerHTML = '<filter id="fl-glow" x="-60%" y="-60%" width="220%" height="220%">' +
            '<feGaussianBlur stdDeviation="3.2" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>' +
            '<radialGradient id="fl-vignette" cx="50%" cy="45%" r="65%"><stop offset="0%" stop-color="var(--fl-teal)" stop-opacity=".05"/><stop offset="100%" stop-color="var(--fl-teal)" stop-opacity="0"/></radialGradient>';
        svg.appendChild(defs);
        world = O.svgEl('g', { id: 'fleet-topo-world' });
        svg.appendChild(world);

        world.appendChild(O.svgEl('ellipse', { cx: W / 2, cy: H / 2, rx: W * 0.5, ry: H * 0.5, fill: 'url(#fl-vignette)', stroke: 'none' }));
        layerLinks = O.svgEl('g', { class: 'fl-links' });
        layerRoam = O.svgEl('g', { class: 'fl-roams' });
        layerRings = O.svgEl('g', { class: 'fl-rings' });
        layerCats = O.svgEl('g', { class: 'fl-cats' });
        layerNodes = O.svgEl('g', { class: 'fl-nodes' });
        layerLabels = O.svgEl('g', { class: 'fl-labels' });
        world.appendChild(layerLinks);
        world.appendChild(layerRoam);
        world.appendChild(layerRings);
        world.appendChild(layerNodes);
        world.appendChild(layerCats);
        world.appendChild(layerLabels);

        hubs = {};
        cats = {};
        var gp = gatewayPositions();
        var newNodes = {};

        // gateways
        S.gates.forEach(function (g) {
            var p = gp[g.id];
            if (!p) return;
            var grp = O.svgEl('g', {
                class: 'fl-hub', transform: 'translate(' + p.x + ',' + p.y + ')',
                'data-key': g.id, tabindex: '0', role: 'button',
                'aria-label': (g.name || g.id) + ', gateway cluster. Click to pin, click again for diagnostics. Badge expands or collapses.'
            });
            grp.innerHTML =
                '<circle class="hub-plate" r="36"></circle>' +
                '<circle class="hub-core" r="25"></circle>' +
                '<path class="hub-icon" d="M-10 2h20M0 -8v20M-7 10h14" stroke-width="1.6" stroke-linecap="round" fill="none"></path>' +
                '<text class="hub-label" x="0" y="51" text-anchor="middle">' + O.esc(g.name || g.ip || 'Gateway') + '</text>' +
                '<text class="hub-sub" x="0" y="62" text-anchor="middle">' + O.esc((g.device_count || 0) + ' devices') + '</text>' +
                '<g class="hub-open" transform="translate(25,-25)"><circle r="8" fill="var(--fl-panel)" stroke="var(--fl-line-strong)"></circle>' +
                '<text class="hub-badge" x="0" y="3.4" text-anchor="middle">' + (S.expandedGateways[g.id] ? '−' : '+') + '</text></g>';
            grp.addEventListener('click', function (ev) {
                ev.stopPropagation();
                O.select(g.id);
            });
            var badge = grp.querySelector('.hub-open');
            if (badge) {
                badge.setAttribute('role', 'button');
                badge.setAttribute('aria-label', 'Expand or collapse gateway cluster');
                badge.addEventListener('click', function (ev) {
                    ev.stopPropagation();
                    O.toggleGateway(g.id);
                });
            }
            grp.addEventListener('mouseenter', function () { O.hover(g.id); });
            grp.addEventListener('mouseleave', function () { O.clearHover(); });
            grp.addEventListener('keydown', function (ev) { if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); grp.dispatchEvent(new MouseEvent('click')); } });
            layerCats.appendChild(grp);
            hubs[g.id] = { x: p.x, y: p.y, el: grp, ref: g };

            if (!S.expandedGateways[g.id]) return;

            var catKeys = Object.keys(S.catByKey).filter(function (ck) {
                return S.devices.some(function (d) { return d.gateway_id === g.id && d.category === ck; });
            });
            catKeys.forEach(function (ck, i) {
                var slot = catSlot(i, catKeys.length, p);
                var count = S.devices.filter(function (d) { return d.gateway_id === g.id && d.category === ck; }).length;
                var cd = catDims(S.catByKey[ck].label, count);
                var cg = O.svgEl('g', {
                    class: 'fl-cat' + (S.expandedCategories[ck] ? ' is-open' : ''),
                    transform: 'translate(' + slot.x + ',' + slot.y + ')',
                    'data-cat': ck, 'data-gw': g.id, tabindex: '0', role: 'button',
                    'aria-label': S.catByKey[ck].label + ' cluster, ' + count + ' devices. Click to pin, click again for diagnostics. Chevron expands.'
                });
                cg.innerHTML =
                    '<rect class="cat-plate" x="' + (-cd.w / 2) + '" y="' + (-cd.h / 2) + '" width="' + cd.w + '" height="' + cd.h + '" rx="9"></rect>' +
                    '<circle cx="' + (-cd.w / 2 + 12) + '" cy="0" r="3.2" fill="' + O.categoryColor(ck) + '"></circle>' +
                    '<text class="cat-count" x="' + (-cd.w / 2 + 21) + '" y="4">' + count + '</text>' +
                    '<text class="cat-label" x="' + (-cd.w / 2 + 21 + String(count).length * 7 + 4) + '" y="4">' + O.esc(S.catByKey[ck].label) + '</text>' +
                    '<path class="cat-chev" d="M' + (cd.w / 2 - 11) + ' -3l4 3-4 3" fill="none" stroke="var(--fl-faint)" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round"' +
                    (S.expandedCategories[ck] ? ' transform="rotate(90 ' + (cd.w / 2 - 11) + ' 0)"' : '') + '></path>';
                var ckey = O.clusterKey(g.id, ck);
                cg.addEventListener('click', function (ev) {
                    ev.stopPropagation();
                    O.select(ckey);
                });
                var chev = cg.querySelector('.cat-chev');
                if (chev) {
                    chev.setAttribute('aria-hidden', 'true');
                    chev.addEventListener('click', function (ev) {
                        ev.stopPropagation();
                        O.toggleCategory(ck);
                    });
                }
                cg.addEventListener('mouseenter', function () { O.hover(ckey); });
                cg.addEventListener('mouseleave', function () { O.clearHover(); });
                cg.addEventListener('keydown', function (ev) { if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); cg.dispatchEvent(new MouseEvent('click')); } });
                layerCats.appendChild(cg);
                if (!cats[ck]) cats[ck] = [];
                cats[ck].push({ x: slot.x, y: slot.y, el: cg, gw: g.id, ref: S.catByKey[ck], w: cd.w });
            });
        });

        settleCatPills();

        // nodes
        S.devices.forEach(function (d) {
            if (d.is_gateway) return;
            var visible = d.quarantined || (S.expandedGateways[d.gateway_id] && S.expandedCategories[d.category]);
            var target = deviceTarget(d);
            var prior = nodes[d.key];
            var start = prior ? { x: prior.x, y: prior.y } : (hubs[d.gateway_id] ? { x: hubs[d.gateway_id].x + (Math.random() - 0.5) * 40, y: hubs[d.gateway_id].y + (Math.random() - 0.5) * 40 } : { x: W / 2, y: H / 2 });
            var nd = prior || { x: start.x, y: start.y, vx: 0, vy: 0, phase: Math.random() * 6.28, gw: d.gateway_id };
            nd.ref = d; nd.tx = target.x; nd.ty = target.y; nd.visible = visible; nd.gw = d.gateway_id; nd.gwOld = prior ? prior.gw : d.gateway_id;
            nd.q = !!d.quarantined;
            nd.el = null;
            nodes[d.key] = nd;
            newNodes[d.key] = nd;
        });

        // prune removed
        Object.keys(nodes).forEach(function (k) { if (!newNodes[k]) delete nodes[k]; });

        // draw visible nodes
        Object.keys(nodes).forEach(function (k) {
            var nd = nodes[k], d = nd.ref;
            if (!nd.visible) return;
            var grp = O.svgEl('g', {
                class: 'fl-node ' + sclass(d), transform: 'translate(' + nd.x + ',' + nd.y + ')',
                'data-key': k, tabindex: '0', role: 'button',
                'aria-label': (d.name || d.ip) + ', ' + O.healthOf(d) + '. Open diagnostics.'
            });
            grp.innerHTML =
                '<circle class="node-halo" r="15"></circle>' +
                '<circle class="node-qring" r="12"></circle>' +
                '<circle class="node-dot" r="' + (d.quarantined ? 5.5 : 6.2) + '"></circle>' +
                '<text class="node-label" x="0" y="' + (nd.q ? -13 : 19) + '" text-anchor="middle">' + O.esc(d.name || d.ip || '') + '</text>' +
                (labelsAlways ? '<text class="node-sub" x="0" y="28" text-anchor="middle">' + O.esc(d.ip || '') + '</text>' : '');
            grp.addEventListener('click', function (ev) { ev.stopPropagation(); O.select(k); });
            grp.addEventListener('mouseenter', function () { O.hover(k); showTip(k, ev); });
            grp.addEventListener('mouseleave', function () { O.clearHover(); hideTip(); });
            grp.addEventListener('keydown', function (ev) { if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); O.select(k); } });
            layerNodes.appendChild(grp);
            nd.el = grp;
            if (nd.gwOld && nd.gw && nd.gwOld !== nd.gw) {
                spawnRoam(k, nd.gwOld, nd.gw, nd);
                nd.x = hubs[nd.gwOld] ? hubs[nd.gwOld].x : nd.x;
                nd.y = hubs[nd.gwOld] ? hubs[nd.gwOld].y : nd.y;
            }
        });

        // quarantine perimeter
        drawQuarantineZone();

        // links
        drawLinks();

        // attach host
        host.appendChild(svg);
        bindPanZoom();
        applyView();
        built = true;
        update();

        if (S.selected && nodes[S.selected] && nodes[S.selected].el) {
            // keep selection visible after rebuild
            nodes[S.selected].el.classList.add('is-selected');
        }
        var empty = document.getElementById('fleet-topo-empty');
        if (empty) empty.classList.toggle('is-on', !S.devices.length);
    }

    function drawQuarantineZone() {
        var q = S.devices.filter(function (d) { return d.quarantined && !d.is_gateway; });
        var cx = W / 2, cy = H / 2, rx = W * 0.455, ry = H * 0.44;
        if (!q.length) return;
        var zone = O.svgEl('ellipse', { class: 'fl-quarantine-zone', cx: cx, cy: cy, rx: rx, ry: ry });
        layerCats.insertBefore(zone, layerCats.firstChild);
        var lbl = O.svgEl('text', { class: 'fl-zone-label', x: 12, y: 16, 'text-anchor': 'start' });
        lbl.textContent = 'QUARANTINE PERIMETER · ' + q.length + ' UNFINGERPRINTED';
        layerCats.insertBefore(lbl, zone.nextSibling);
        q.forEach(function (d, i) {
            var a = -Math.PI / 2 + (i * Math.PI * 2 / Math.max(q.length, 1)) + 0.22;
            var nd = nodes[d.key];
            if (!nd) return;
            nd.tx = cx + Math.cos(a) * rx;
            nd.ty = cy + Math.sin(a) * ry;
            nd.perimeter = true;
        });
    }

    function deviceTarget(d) {
        if (d.quarantined) {
            var q = S.devices.filter(function (x) { return x.quarantined && !x.is_gateway; });
            var qi = q.findIndex(function (x) { return x.key === d.key; });
            var a = -Math.PI / 2 + (Math.max(0, qi) * Math.PI * 2 / Math.max(1, q.length)) + 0.22;
            return { x: W / 2 + Math.cos(a) * W * 0.455, y: H / 2 + Math.sin(a) * H * 0.44 };
        }
        var list = cats[d.category] || [];
        var c = list.filter(function (x) { return x.gw === d.gateway_id; })[0] || list[0];
        if (!c || !S.expandedGateways[d.gateway_id] || !S.expandedCategories[d.category]) {
            var hub = hubs[d.gateway_id];
            var sib = S.devices.filter(function (x) { return x.category === d.category && x.gateway_id === d.gateway_id && !x.quarantined; });
            var idx = sib.findIndex(function (x) { return x.key === d.key; });
            var base = hub || { x: W / 2, y: H / 2 };
            var aa = -0.8 + (Math.max(0, idx) * 0.55) % (Math.PI * 1.6);
            return { x: base.x + Math.cos(aa) * 8, y: base.y + Math.sin(aa) * 8 };
        }
        var sibs = S.devices.filter(function (x) { return x.category === d.category && x.gateway_id === d.gateway_id && !x.quarantined; });
        var i = sibs.findIndex(function (x) { return x.key === d.key; });
        var per = 9;
        var ring = Math.floor(i / per);
        var slot = i % per;
        var nInRing = Math.min(per, sibs.length - ring * per);
        var da = (slot / Math.max(1, nInRing)) * Math.PI * 2 + ring * 0.45;
        var rad = 46 + ring * 27;
        var out = Math.atan2(c.y - (hubs[d.gateway_id] ? hubs[d.gateway_id].y : H / 2), c.x - (hubs[d.gateway_id] ? hubs[d.gateway_id].x : W / 2));
        return { x: c.x + Math.cos(da) * rad + Math.cos(out) * ring * 6, y: c.y + Math.sin(da) * rad * 0.86 + Math.sin(out) * ring * 6 };
    }

    /* ---------------- links ---------------- */
    function drawLinks() {
        layerLinks.innerHTML = '';
        var n = 0;
        S.devices.forEach(function (d) {
            if (d.is_gateway) return;
            var nd = nodes[d.key];
            if (!nd) return;
            var path = O.svgEl('path', {
                class: 'fl-link ' + (d.quarantined ? 'is-quarantine' : d.link_kind === 'wireless' ? 'is-wireless' : 'is-wired') +
                    (O.healthOf(d) === 'offline' ? ' is-hot' : ''),
                'data-key': d.key
            });
            layerLinks.appendChild(path);
            nd.linkEl = path;
            n++;
        });
    }

    function linkTarget(nd) {
        var d = nd.ref;
        if (d.quarantined) return hubs[d.gateway_id] || { x: W / 2, y: H / 2 };
        if (S.expandedCategories[d.category]) {
            var list = cats[d.category] || [];
            var c = list.filter(function (x) { return x.gw === d.gateway_id; })[0];
            if (c) return c;
        }
        return hubs[d.gateway_id] || { x: W / 2, y: H / 2 };
    }

    function updateLinkPaths() {
        Object.keys(nodes).forEach(function (k) {
            var nd = nodes[k];
            if (!nd.linkEl || !nd.visible) { if (nd.linkEl) nd.linkEl.style.display = 'none'; return; }
            nd.linkEl.style.display = '';
            var t = linkTarget(nd);
            var mx = (nd.x + t.x) / 2, my = (nd.y + t.y) / 2;
            var dx = t.x - nd.x, dy = t.y - nd.y, dist = Math.sqrt(dx * dx + dy * dy) || 1;
            var bow = Math.min(34, dist * 0.13) * (nd.perimeter ? 1.5 : 1);
            var cx = mx - (dy / dist) * bow, cy = my + (dx / dist) * bow;
            nd.linkEl.setAttribute('d', 'M' + nd.x.toFixed(1) + ',' + nd.y.toFixed(1) + ' Q' + cx.toFixed(1) + ',' + cy.toFixed(1) + ' ' + t.x.toFixed(1) + ',' + t.y.toFixed(1));
        });
    }

    /* ---------------- rings / roam ---------------- */
    function drawRings() {
        layerRings.innerHTML = '';
        S.devices.forEach(function (d) {
            if (d.is_gateway) return;
            var nd = nodes[d.key];
            if (!nd || !nd.visible) return;
            var hs = O.healthOf(d);
            if (hs === 'healthy') return;
            var ring = O.svgEl('circle', { class: 'fl-ring ' + (hs === 'degraded' ? 'is-medium' : ''), r: hs === 'offline' ? 13 : 15 });
            ring.setAttribute('cx', '0'); ring.setAttribute('cy', '0');
            var g = O.svgEl('g', { transform: 'translate(' + nd.x + ',' + nd.y + ')' });
            g.appendChild(ring);
            layerRings.appendChild(g);
            nd.ringEl = g;
        });
        // gateway outage rings
        S.gates.forEach(function (g) {
            var offline = S.devices.filter(function (d) { return d.gateway_id === g.id && O.healthOf(d) === 'offline'; }).length;
            var degraded = S.devices.filter(function (d) { return d.gateway_id === g.id && O.healthOf(d) === 'degraded'; }).length;
            var h = hubs[g.id];
            if (!h || (offline === 0 && degraded === 0 && String(g.state).toLowerCase() !== 'degraded')) return;
            var gEl = O.svgEl('g', { transform: 'translate(' + h.x + ',' + h.y + ')' });
            var r1 = O.svgEl('circle', { class: 'fl-ring', r: 40 }); r1.setAttribute('cx', 0); r1.setAttribute('cy', 0);
            gEl.appendChild(r1);
            if (offline > 1) {
                var r2 = O.svgEl('circle', { class: 'fl-ring', r: 40, style: 'animation-delay:1.4s' }); r2.setAttribute('cx', 0); r2.setAttribute('cy', 0);
                gEl.appendChild(r2);
            }
            layerRings.appendChild(gEl);
            h.ringEl = gEl;
        });
    }

    function spawnRoam(key, fromId, toId, nd) {
        var a = hubs[fromId], b = hubs[toId];
        if (!a || !b) return;
        var arc = O.svgEl('path', { class: 'fl-roam-arc' });
        var packet = O.svgEl('circle', { class: 'fl-roam-packet', r: 4 });
        var label = O.svgEl('text', { class: 'fl-roam-label', 'text-anchor': 'middle' });
        label.textContent = (nd && nd.ref ? nd.ref.name : 'device') + ' roaming';
        layerRoam.appendChild(arc); layerRoam.appendChild(packet); layerRoam.appendChild(label);
        var mx = (a.x + b.x) / 2, my = (a.y + b.y) / 2 - Math.min(110, Math.abs(b.x - a.x) * 0.28 + 50);
        roamAnims.push({ key: key, a: a, b: b, mx: mx, my: my, t0: performance.now(), dur: 4200, arc: arc, packet: packet, label: label });
        if (nd) { nd.x = a.x; nd.y = a.y; nd.vx = 0; nd.vy = 0; }
    }

    function tickRoam(now) {
        for (var i = roamAnims.length - 1; i >= 0; i--) {
            var r = roamAnims[i];
            var t = (now - r.t0) / r.dur;
            if (t >= 1) { r.arc.remove(); r.packet.remove(); r.label.remove(); roamAnims.splice(i, 1); continue; }
            var d = 'M' + r.a.x + ',' + r.a.y + ' Q' + r.mx + ',' + r.my + ' ' + r.b.x + ',' + r.b.y;
            r.arc.setAttribute('d', d);
            var e = t < 0.5 ? 2 * t * t : 1 - Math.pow(-2 * t + 2, 2) / 2;
            var x = (1 - e) * (1 - e) * r.a.x + 2 * (1 - e) * e * r.mx + e * e * r.b.x;
            var y = (1 - e) * (1 - e) * r.a.y + 2 * (1 - e) * e * r.my + e * e * r.b.y;
            r.packet.setAttribute('cx', x.toFixed(1)); r.packet.setAttribute('cy', y.toFixed(1));
            r.label.setAttribute('x', (r.mx).toFixed(1)); r.label.setAttribute('y', (r.my - 6).toFixed(1));
            r.arc.style.opacity = String(1 - Math.max(0, t - 0.7) / 0.3);
            r.packet.style.opacity = String(1 - Math.max(0, t - 0.8) / 0.2);
            r.label.style.opacity = String(1 - Math.max(0, t - 0.7) / 0.3);
        }
    }

    /* ---------------- physics ---------------- */
    function step(now) {
        if (!built) return;
        var dt = 1 / 60;
        Object.keys(nodes).forEach(function (k) {
            var nd = nodes[k];
            if (!nd.visible) return;
            var wob = Math.sin(now / 1900 + nd.phase) * 2.2;
            var tx = nd.tx + (nd.perimeter ? Math.cos(nd.phase + now / 2600) * 2.4 : wob);
            var ty = nd.ty + (nd.perimeter ? Math.sin(nd.phase + now / 2600) * 2.4 : Math.cos(now / 2100 + nd.phase) * 1.8);
            nd.vx += (tx - nd.x) * 0.085;
            nd.vy += (ty - nd.y) * 0.085;
            nd.vx *= 0.80; nd.vy *= 0.80;
            nd.x += nd.vx; nd.y += nd.vy;
        });
        // collision pass for siblings
        var visible = Object.keys(nodes).map(function (k) { return nodes[k]; }).filter(function (n) { return n.visible && !n.perimeter; });
        for (var i = 0; i < visible.length; i++) {
            for (var j = i + 1; j < visible.length; j++) {
                var a = visible[i], b = visible[j];
                if (a.ref.category !== b.ref.category || a.ref.gateway_id !== b.ref.gateway_id) continue;
                var dx = b.x - a.x, dy = b.y - a.y;
                var d2 = dx * dx + dy * dy;
                if (d2 < 256 && d2 > 0.01) {
                    var d = Math.sqrt(d2), push = (16 - d) * 0.5;
                    var ux = dx / d, uy = dy / d;
                    a.x -= ux * push; a.y -= uy * push;
                    b.x += ux * push; b.y += uy * push;
                }
            }
        }
        Object.keys(nodes).forEach(function (k) {
            var nd = nodes[k];
            if (!nd.visible) { if (nd.linkEl) nd.linkEl.style.display = 'none'; return; }
            if (nd.el) nd.el.setAttribute('transform', 'translate(' + nd.x.toFixed(1) + ',' + nd.y.toFixed(1) + ')');
            if (nd.linkEl) nd.linkEl.style.display = '';
            if (nd.ringEl) nd.ringEl.setAttribute('transform', 'translate(' + nd.x.toFixed(1) + ',' + nd.y.toFixed(1) + ')');
        });
        updateLinkPaths();
        tickRoam(now);
    }

    /* ---------------- highlight ---------------- */
    function pillHit(grp, cat, gw) {
        if (!grp || !grp.categories[cat]) return false;
        if (grp.kind === 'category' && grp.gateway_id && grp.gateway_id !== gw) return false;
        return !!grp.gatewayIds[gw];
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
                var nd = nodes[k];
                return !!nd && nd.ref.gateway_id === t.dev.gateway_id && nd.ref.category === t.dev.category;
            }
            return false;
        }
        Object.keys(nodes).forEach(function (k) {
            var nd = nodes[k];
            if (!nd.el) return;
            var isFocus = targets.some(function (t) { return hit(t, k); });
            var dim = targets.length > 0 && !isFocus;
            nd.el.classList.toggle('is-hovered', S.hovered === k || member(hovGrp, k));
            nd.el.classList.toggle('is-selected', S.selected === k || member(selGrp, k));
            nd.el.classList.toggle('is-dim', dim);
            if (nd.linkEl) {
                nd.linkEl.classList.toggle('is-dim', dim);
                nd.linkEl.classList.toggle('is-selected', isFocus);
            }
        });
        Object.keys(hubs).forEach(function (id) {
            var h = hubs[id];
            var isSel = S.selected === id || (selGrp && selGrp.kind === 'gateway' && selGrp.gateway_id === id);
            var isHov = S.hovered === id || (hovGrp && hovGrp.kind === 'gateway' && hovGrp.gateway_id === id);
            h.el.classList.toggle('is-selected', isSel);
            h.el.classList.toggle('is-hovered', isHov);
        });
        document.querySelectorAll('#fleet-topo .fl-cat').forEach(function (c) {
            var ck = c.getAttribute('data-cat');
            var cgw = c.getAttribute('data-gw');
            var ckey = O.clusterKey(cgw, ck);
            var isFocusPill = targets.some(function (t) {
                return t.key === ckey || (t.grp && pillHit(t.grp, ck, cgw));
            });
            var isSelPill = S.selected === ckey || (selGrp && pillHit(selGrp, ck, cgw));
            var isHovPill = S.hovered === ckey || (hovGrp && pillHit(hovGrp, ck, cgw));
            c.classList.toggle('is-selected', !!isSelPill);
            c.classList.toggle('is-hovered', !!isHovPill);
            c.classList.toggle('is-dim', groupTargets.length > 0 && !isFocusPill);
        });
    }

    function focus(key) {
        if (!built || !nodes[key]) return;
        var nd = nodes[key];
        var sx = nd.x * view.k + view.x, sy = nd.y * view.k + view.y;
        if (sx < 80 || sx > W - 80 || sy < 110 || sy > H - 60) {
            view.k = Math.max(view.k, 1.15);
            view.x = W / 2 - nd.x * view.k;
            view.y = H / 2 - nd.y * view.k;
            applyView(true);
        }
        if (nd.el) {
            nd.el.classList.add('is-selected');
            setTimeout(function () { nd.el && nd.el.classList.remove('is-selected'); }, 1600);
        }
    }

    /* ---------------- tip ---------------- */
    function showTip(key, ev) {
        var d = S.devByKey[key];
        var tip = document.getElementById('fleet-tip');
        if (!d || !tip) return;
        var h = d.health || {};
        var hs = O.healthOf(d);
        var c = ['var(--fl-healthy)', 'var(--fl-degraded)', 'var(--fl-offline)'][['healthy', 'degraded', 'offline'].indexOf(hs)] || 'var(--fl-unidentified)';
        tip.innerHTML = '<div class="fleet-tip-title"><i class="dot" style="--c:' + c + '"></i>' + O.esc(d.name || d.ip) + '</div>' +
            '<div class="fleet-tip-ip">' + O.esc(d.ip || '') + ' · ' + O.esc(d.category_label || d.category || '') + '</div>' +
            '<div class="fleet-tip-grid">' +
            '<div><span>State</span><b>' + O.esc(hs) + '</b></div>' +
            '<div><span>Latency</span><b>' + (h.latency_ms != null ? O.fmtMs(h.latency_ms) : '—') + '</b></div>' +
            '<div><span>Decay</span><b>' + (h.score != null ? Math.round(h.score) + '%' : '—') + '</b></div>' +
            '<div><span>Gateway</span><b>' + O.esc(d.gateway_name || '—') + '</b></div>' +
            '</div><div class="fleet-tip-hint">Click to pin highlight · click again for diagnostics</div>';
        var r = ev.currentTarget.getBoundingClientRect();
        tip.style.left = Math.min(window.innerWidth - 290, r.right + 12) + 'px';
        tip.style.top = Math.max(10, r.top - 10) + 'px';
        tip.classList.add('is-on');
    }
    function hideTip() { var t = document.getElementById('fleet-tip'); if (t) t.classList.remove('is-on'); }

    function openGatewayDrawer(g) {
        var dev = {
            key: g.id, name: g.name || g.ip, ip: g.ip, gateway_name: 'network core', is_gateway: true,
            type: 'gateway', category_label: 'Infrastructure', category: 'network', gateway_id: g.id,
            health: { state: g._state || 'healthy', score: Math.round((g.healthy || 0) / Math.max(1, g.device_count || 1) * 100), latency_ms: g.latency_ms, loss_pct: g.packet_loss },
            risk: 'low', quarantined: false, last_seen: new Date().toISOString()
        };
        S.devByKey[g.id] = dev;
        S.selected = g.id;
        V.highlightTopology && V.highlightTopology(g.id);
        var head = document.getElementById('fleet-drawer-head');
        var body = document.getElementById('fleet-drawer-body');
        if (!head || !body) return;
        var offline = S.devices.filter(function (d) { return d.gateway_id === g.id && O.healthOf(d) === 'offline'; }).length;
        head.innerHTML = '<div class="fleet-drawer-top"><div><div class="fleet-drawer-eyebrow">Gateway diagnostics</div><h2>' + O.esc(g.name || g.ip) + '</h2>' +
            '<div class="fleet-drawer-ip"><span>' + O.esc(g.ip || '') + '</span><span>·</span><span>parent cluster</span></div></div>' +
            '<button class="fleet-drawer-close" onclick="FleetOps.closeDrawer()"><i class="fas fa-xmark"></i></button></div>' +
            '<div class="fleet-drawer-pills"><span class="fleet-pill is-' + O.esc(g._state || 'healthy') + '">' + O.esc(g._state || 'healthy') + '</span>' +
            '<span class="fleet-pill">' + (g.device_count || 0) + ' devices</span>' + (offline ? '<span class="fleet-pill is-offline">' + offline + ' offline</span>' : '') + '</div>';
        var kids = S.devices.filter(function (d) { return d.gateway_id === g.id; });
        body.innerHTML = '<div class="fleet-metrics">' +
            '<div class="fleet-metric"><span>Devices</span><b>' + kids.length + '</b></div>' +
            '<div class="fleet-metric"><span>Healthy</span><b>' + kids.filter(function (d) { return O.healthOf(d) === 'healthy'; }).length + '</b></div>' +
            '<div class="fleet-metric"><span>Degraded</span><b>' + kids.filter(function (d) { return O.healthOf(d) === 'degraded'; }).length + '</b></div>' +
            '<div class="fleet-metric"><span>Offline</span><b>' + offline + '</b></div>' +
            '<div class="fleet-metric"><span>Quarantined</span><b>' + kids.filter(function (d) { return d.quarantined; }).length + '</b></div>' +
            '<div class="fleet-metric"><span>State</span><b>' + O.esc(g.state || 'healthy') + '</b></div>' +
            '</div><div class="fleet-section"><div class="fleet-section-head"><h3>Cluster members</h3><span>top 12 by risk</span></div><div class="fleet-facts">' +
            kids.slice(0, 12).map(function (d) { return '<div class="fleet-fact"><span><i class="fas fa-circle" style="font-size:.4rem;color:var(--fl-' + O.healthOf(d) + ')"></i> ' + O.esc(d.name) + '</span><b>' + O.esc(d.ip) + '</b></div>'; }).join('') +
            '</div></div><div class="fleet-drawer-actions"><button class="fleet-act is-primary" onclick="FleetOps.toggleGateway(\'' + O.esc(g.id) + '\');FleetOps.closeDrawer()">' +
            (S.expandedGateways[g.id] ? 'Collapse cluster' : 'Expand cluster') + '</button></div>' +
            '<div class="fleet-drawer-note">This panel is shared with every visualization. Selecting a member device retargets it.</div>';
        O.openDrawer();
    }

    /* ---------------- pan / zoom ---------------- */
    function bindPanZoom() {
        svg.addEventListener('wheel', function (ev) {
            ev.preventDefault();
            var rect = svg.getBoundingClientRect();
            var mx = ev.clientX - rect.left, my = ev.clientY - rect.top;
            var k2 = Math.max(0.5, Math.min(2.8, view.k * (ev.deltaY < 0 ? 1.09 : 0.915)));
            view.x = mx - (mx - view.x) * (k2 / view.k);
            view.y = my - (my - view.y) * (k2 / view.k);
            view.k = k2;
            applyView();
        }, { passive: false });
        svg.addEventListener('pointerdown', function (ev) {
            if (ev.target.closest('.fl-node,.fl-cat,.fl-hub')) return;
            dragging = true; moved = false;
            dragStart = { x: ev.clientX, y: ev.clientY, vx: view.x, vy: view.y };
            svg.classList.add('is-panning');
            svg.setPointerCapture(ev.pointerId);
        });
        svg.addEventListener('pointermove', function (ev) {
            if (!dragging) return;
            var dx = ev.clientX - dragStart.x, dy = ev.clientY - dragStart.y;
            if (Math.abs(dx) + Math.abs(dy) > 3) moved = true;
            view.x = dragStart.vx + dx; view.y = dragStart.vy + dy;
            applyView();
        });
        svg.addEventListener('pointerup', function () { dragging = false; svg.classList.remove('is-panning'); });
        svg.addEventListener('pointercancel', function () { dragging = false; svg.classList.remove('is-panning'); });
        svg.addEventListener('dblclick', function (ev) {
            if (ev.target.closest('.fl-node,.fl-cat,.fl-hub')) return;
            view = { k: 1, x: 0, y: 0 }; applyView(true);
        });
        svg.addEventListener('click', function (ev) {
            if (moved) return;
            if (ev.target.closest('.fl-node,.fl-cat,.fl-hub')) return;
            O.clearSelection();
        });
    }

    function applyView(animate) {
        if (!world) return;
        if (animate) {
            world.style.transition = 'transform .45s cubic-bezier(.2,.8,.3,1)';
            setTimeout(function () { if (world) world.style.transition = ''; }, 500);
        }
        world.setAttribute('transform', 'translate(' + view.x.toFixed(1) + ',' + view.y.toFixed(1) + ') scale(' + view.k.toFixed(3) + ')');
    }

    function resetView() { view = { k: 1, x: 0, y: 0 }; applyView(true); }

    /* ---------------- update / tick ---------------- */
    function update() {
        if (!built) return;
        if (S.devices.length > 30) svg.setAttribute('class', 'is-dense');
        else svg.removeAttribute('class');
        dims();
        // recompute targets if filters changed
        Object.keys(nodes).forEach(function (k) {
            var nd = nodes[k];
            var d = nd.ref;
            var visible = d.quarantined || (S.expandedGateways[d.gateway_id] && S.expandedCategories[d.category]);
            if (visible !== nd.visible) {
                // visibility toggled: rebuild the node DOM
                if (visible && !nd.el) {
                    buildNodeElement(nd);
                } else if (!visible && nd.el) {
                    nd.el.remove(); nd.el = null;
                }
                nd.visible = visible;
            }
            var t = deviceTarget(d);
            nd.tx = t.x; nd.ty = t.y;
            if (nd.el) {
                var ndClass = 'fl-node ' + sclass(d);
                if (nd.el.classList.contains('is-selected')) ndClass += ' is-selected';
                if (nd.el.classList.contains('is-hovered')) ndClass += ' is-hovered';
                if (nd.el.classList.contains('is-dim')) ndClass += ' is-dim';
                nd.el.setAttribute('class', ndClass);
            }
        });
        drawLinks();
        drawRings();
        highlight();
    }

    function buildNodeElement(nd) {
        var k = nd.ref.key, d = nd.ref;
        var grp = O.svgEl('g', {
            class: 'fl-node ' + sclass(d), transform: 'translate(' + nd.x + ',' + nd.y + ')',
            'data-key': k, tabindex: '0', role: 'button'
        });
        grp.innerHTML = '<circle class="node-halo" r="15"></circle><circle class="node-qring" r="12"></circle>' +
            '<circle class="node-dot" r="' + (d.quarantined ? 5.5 : 6.2) + '"></circle>' +
            '<text class="node-label" x="0" y="' + (d.quarantined ? -13 : 19) + '" text-anchor="middle">' + O.esc(d.name || d.ip) + '</text>';
        grp.addEventListener('click', function (ev) { ev.stopPropagation(); O.select(k); });
        grp.addEventListener('mouseenter', function (ev) { O.hover(k); showTip(k, ev); });
        grp.addEventListener('mouseleave', function () { O.clearHover(); hideTip(); });
        layerNodes.appendChild(grp);
        nd.el = grp;
    }

    V.buildTopology = function () {
        host = document.getElementById('fleet-topo');
        if (!host) return;
        built = false;
        build();
    };
    V.updateTopology = update;
    V.tickTopology = function (now) {
        if (!O.isVisible() || !built) return;
        step(now);
    };
    V.pulseTopology = function (key) {
        var nd = nodes[key];
        if (!nd || !nd.el) return;
        var dot = nd.el.querySelector('.node-halo');
        if (!dot) return;
        dot.classList.remove('is-pulse');
        void dot.getBoundingClientRect();
        dot.classList.add('is-pulse');
        setTimeout(function () { dot.classList.remove('is-pulse'); }, 900);
    };
    V.roamTopology = function (key, fromId, toId) {
        var nd = nodes[key];
        if (!nd) return;
        spawnRoam(key, fromId, toId, nd);
        nd.gw = toId;
        nd.tx = deviceTarget(nd.ref).x; nd.ty = deviceTarget(nd.ref).y;
        if (nd.el) {
            nd.el.style.filter = 'drop-shadow(0 0 8px var(--fl-violet))';
            setTimeout(function () { if (nd.el) nd.el.style.filter = ''; }, 1600);
        }
        if (S.devByKey[key]) S.devByKey[key].gateway_id = toId;
    };
    V.highlightTopology = highlight;
    V.focusTopology = focus;
    V.resetTopology = resetView;

    window.FleetTopoOps = {
        expandAll: function () { O.expandAll(); },
        collapseAll: function () { O.collapseAll(); },
        reset: resetView,
        toggleLabels: function () {
            labelsAlways = !labelsAlways;
            document.querySelectorAll('#fleet-topo .node-sub').forEach(function (n) { n.remove(); });
            Object.keys(nodes).forEach(function (k) {
                var nd = nodes[k];
                if (labelsAlways && nd.el && !nd.q) {
                    var t = O.svgEl('text', { class: 'node-sub', x: 0, y: 28, 'text-anchor': 'middle' });
                    t.textContent = nd.ref.ip || '';
                    nd.el.appendChild(t);
                }
            });
            O.toast(labelsAlways ? 'Address labels shown' : 'Address labels hidden');
        }
    };
})();
