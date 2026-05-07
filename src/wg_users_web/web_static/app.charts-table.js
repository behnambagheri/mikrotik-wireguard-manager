    function parseWgHealthLine(line) {
      const s = String(line || '').trim();
      const m = s.match(/^([^:]+):\s*peers=(\d+)\s+active<=3m=(\d+)\s+bw=([^\s]+\s+[^\s]+)\s+running=(true|false)$/i);
      if (!m) return null;
      return {
        iface: m[1],
        peers: m[2],
        active: m[3],
        bw: m[4],
        running: m[5].toLowerCase() === 'true',
      };
    }
    function renderWgHealth(lines) {
      const el = byId('wgHealth');
      const items = Array.isArray(lines) ? lines : [];
      const updatePulse = (parsedItems) => {
        const totalPeers = parsedItems.reduce((acc, x) => acc + Number(x.peers || 0), 0);
        const activePeers = parsedItems.reduce((acc, x) => acc + Number(x.active || 0), 0);
        byId('pulsePeers').textContent = String(totalPeers);
        byId('pulseActive').textContent = String(activePeers);
        byId('pulseBandwidth').textContent = parsedItems.length ? txt(parsedItems[parsedItems.length - 1].bw) : '-';
        byId('pulseActiveBar').style.width = `${totalPeers > 0 ? Math.min(100, (activePeers / totalPeers) * 100) : 0}%`;
      };
      if (!items.length) {
        el.innerHTML = '<div class="meta">No WG interfaces found</div>';
        updatePulse([]);
        return;
      }
      const parsed = items.map(parseWgHealthLine);
      if (parsed.every((x) => x)) {
        updatePulse(parsed);
        el.innerHTML = `<div class="wg-health-list">${parsed.map((x) => `
          <div class="wg-health-item">
            <div class="wg-iface">${txt(x.iface)}</div>
            <span class="wg-tag">peers: ${x.peers}</span>
            <span class="wg-tag">active ≤3m: ${x.active}</span>
            <span class="wg-tag">bw: ${txt(x.bw)}</span>
            <span class="wg-tag ${x.running ? 'ok' : 'bad'}">running: ${x.running ? 'yes' : 'no'}</span>
          </div>
        `).join('')}</div>`;
        return;
      }
      updatePulse([]);
      el.innerHTML = items.map((x) => `<div>${txt(x)}</div>`).join('');
    }
    function metricMax(values) {
      let m = 0;
      for (const v of values) m = Math.max(m, Number(v || 0));
      return m <= 0 ? 1 : m;
    }
    function normalizeRows(rows, valueKey, maxCount = 6) {
      const sorted = [...rows].sort((a, b) => Number(b[valueKey] || 0) - Number(a[valueKey] || 0));
      return sorted.slice(0, maxCount);
    }
    function buildBars(title, rows, valueKey, valueFmt, opts = {}) {
      if (!rows.length) return `<div class="snap-card"><div class="snap-title">${title}</div><div class="snap-empty">No data</div></div>`;
      const maxVal = metricMax(rows.map((r) => r[valueKey]));
      const fillClass = opts.fillClass || '';
      return `<div class="snap-card"><div class="snap-title">${title}</div>${
        rows.map((r) => {
          const v = Number(r[valueKey] || 0);
          const pct = Math.max(0, Math.min(100, (v / maxVal) * 100));
          const label = `${r.is_group_row ? '<span class="snap-kind">GROUP</span>' : ''}${txt(r.name || r.ip || r.peer_id)}`;
          return `<div class="snap-row">
            <div class="snap-label">${label}</div>
            <div class="snap-track"><div class="snap-fill ${fillClass}" style="width:${pct}%;"></div></div>
            <div class="snap-val">${valueFmt(v, r)}</div>
          </div>`;
        }).join('')
      }</div>`;
    }
    function renderSnapshotCharts(rows) {
      const host = byId('snapshotCharts');
      if (!host) return;
      const clients = Array.isArray(rows) ? rows : [];
      if (!clients.length) {
        host.innerHTML = '<div class="snap-card"><div class="snap-title">Snapshot</div><div class="snap-empty">No client data</div></div>';
        return;
      }
      const items = snapshotRowsWithGroups(clients);
      const topDown = normalizeRows(items, 'total_download_bytes');
      const topUp = normalizeRows(items, 'total_upload_bytes');
      const topNow = normalizeRows(items.map((x) => ({ ...x, combined_speed: Number(x.down_speed_bps || 0) + Number(x.up_speed_bps || 0) })), 'combined_speed');

      const quotaRows = items
        .map((x) => {
          const dLim = Number(x.traffic_limit_down_bytes || 0);
          const uLim = Number(x.traffic_limit_up_bytes || 0);
          const dUsed = Number(x.download_since_now_bytes || 0);
          const uUsed = Number(x.upload_since_now_bytes || 0);
          const parts = [];
          if (dLim > 0) parts.push(dUsed / dLim);
          if (uLim > 0) parts.push(uUsed / uLim);
          if (!parts.length) return null;
          const ratio = Math.max(...parts);
          return { ...x, quota_ratio: ratio };
        })
        .filter(Boolean)
        .sort((a, b) => Number(b.quota_ratio || 0) - Number(a.quota_ratio || 0))
        .slice(0, 6);

      const policyCounts = {
        disable: 0,
        throttle: 0,
        trusted_only: 0,
        overlimit_active: 0,
        disabled: 0,
      };
      for (const x of clients) {
        const mode = String(x.overlimit_mode || 'disable');
        if (mode in policyCounts) policyCounts[mode] += 1;
        if (x.overlimit_active) policyCounts.overlimit_active += 1;
        if (String(x.state || '') === 'disabled') policyCounts.disabled += 1;
      }
      const policyRows = [
        { name: 'mode: disable', v: policyCounts.disable },
        { name: 'mode: throttle', v: policyCounts.throttle },
        { name: 'mode: trusted_only', v: policyCounts.trusted_only },
        { name: 'overlimit active', v: policyCounts.overlimit_active },
        { name: 'disabled clients', v: policyCounts.disabled },
      ];
      const policyMax = metricMax(policyRows.map((x) => x.v));
      const policyCard = `<div class="snap-card"><div class="snap-title">Policy Distribution</div>${
        policyRows.map((p) => {
          const pct = Math.max(0, Math.min(100, (p.v / policyMax) * 100));
          return `<div class="snap-row">
            <div class="snap-label">${p.name}</div>
            <div class="snap-track"><div class="snap-fill" style="width:${pct}%;"></div></div>
            <div class="snap-val">${p.v}</div>
          </div>`;
        }).join('')
      }</div>`;

      const hotspots = items
        .map((x) => {
          const q = clientQuotaPct(x);
          const s = clientSpeedPct(x);
          const tags = [];
          if (x.overlimit_active) tags.push({ t: 'over-limit active', c: 'bad' });
          if (q !== null && q >= 100) tags.push({ t: `quota ${q.toFixed(0)}%`, c: 'bad' });
          else if (q !== null && q >= 80) tags.push({ t: `quota ${q.toFixed(0)}%`, c: 'warn' });
          if (s !== null && s >= 92) tags.push({ t: `speed ${s.toFixed(0)}%`, c: s >= 100 ? 'bad' : 'warn' });
          if (!tags.length) return null;
          return { name: x.name || x.ip || x.peer_id, is_group_row: x.is_group_row, tags };
        })
        .filter(Boolean)
        .slice(0, 5);
      const hotspotsCard = !hotspots.length
        ? `<div class="snap-card"><div class="snap-title">Policy Hotspots (Top 5)</div><div class="snap-empty">No touched clients right now</div></div>`
        : `<div class="snap-card"><div class="snap-title">Policy Hotspots (Top 5)</div>${
            hotspots.map((h) => `
              <div style="margin:6px 0;">
                <div class="snap-label" style="color:var(--text);">${h.is_group_row ? '<span class="snap-kind">GROUP</span>' : ''}${txt(h.name)}</div>
                <div class="snap-badges">${h.tags.map((t) => `<span class="snap-badge ${t.c}">${t.t}</span>`).join('')}</div>
              </div>
            `).join('')
          }</div>`;

      const quotaCard = !quotaRows.length
        ? `<div class="snap-card"><div class="snap-title">Quota Usage (limited users)</div><div class="snap-empty">No quota limits configured</div></div>`
        : `<div class="snap-card"><div class="snap-title">Quota Usage (limited users)</div>${
            quotaRows.map((r) => {
              const pct = Math.max(0, Math.min(100, Number(r.quota_ratio || 0) * 100));
              const cls = pct >= 100 ? 'bad' : (pct >= 80 ? 'warn' : '');
              return `<div class="snap-row">
                <div class="snap-label">${r.is_group_row ? '<span class="snap-kind">GROUP</span>' : ''}${txt(r.name || r.ip)}</div>
                <div class="snap-track"><div class="snap-fill ${cls}" style="width:${pct}%;"></div></div>
                <div class="snap-val">${pct.toFixed(0)}%</div>
              </div>`;
            }).join('')
          }</div>`;

      host.innerHTML = [
        buildBars('Top Download (total)', topDown, 'total_download_bytes', (v) => hBytes(v)),
        buildBars('Top Upload (total)', topUp, 'total_upload_bytes', (v) => hBytes(v)),
        buildBars('Current Speed Snapshot', topNow, 'combined_speed', (v) => hBps(v)),
        quotaCard,
        policyCard,
        hotspotsCard,
      ].join('');
    }
    function saveClientColsState() {
      try { localStorage.setItem(CLIENT_COLS_KEY, JSON.stringify({ order: clientColOrder, widths: clientColWidths })); } catch (_) {}
      savePanelSettingsDebounced();
    }
    function loadClientColsState() {
      try {
        const raw = localStorage.getItem(CLIENT_COLS_KEY);
        if (!raw) return;
        const data = JSON.parse(raw);
        if (Array.isArray(data.order)) clientColOrder = data.order.map((x) => String(x || ''));
        if (data.widths && typeof data.widths === 'object') clientColWidths = data.widths;
      } catch (_) {}
    }
    function ensureClientColsOrder() {
      const table = byId('clientsTable');
      if (!table || !table.tHead || !table.tHead.rows.length) return;
      const all = Array.from(table.tHead.rows[0].cells).map((th) => th.dataset.col || '');
      if (!clientColOrder.length) {
        clientColOrder = DEFAULT_CLIENT_COL_ORDER.filter((k) => all.includes(k));
        for (const k of all) if (!clientColOrder.includes(k)) clientColOrder.push(k);
      }
      const set = new Set(all);
      clientColOrder = clientColOrder.filter((k) => set.has(k));
      for (const k of all) if (!clientColOrder.includes(k)) clientColOrder.push(k);
      clientColOrder = clientColOrder.filter((k) => k !== 'sel');
      clientColOrder.unshift('sel');
    }
    function reorderCellsByOrder(row) {
      const map = {};
      for (const cell of Array.from(row.cells)) map[cell.dataset.col || ''] = cell;
      for (const key of clientColOrder) {
        const cell = map[key];
        if (cell) row.appendChild(cell);
      }
    }
    function applyClientColsLayout() {
      const table = byId('clientsTable');
      if (!table) return;
      ensureClientColsOrder();
      const theadRow = table.tHead?.rows?.[0];
      if (!theadRow) return;
      reorderCellsByOrder(theadRow);
      for (const row of Array.from(table.tBodies[0]?.rows || [])) reorderCellsByOrder(row);

      let cg = table.querySelector('colgroup');
      if (!cg) {
        cg = document.createElement('colgroup');
        table.insertBefore(cg, table.tHead);
      }
      cg.innerHTML = '';
      for (const key of clientColOrder) {
        const col = document.createElement('col');
        const w = key === 'sel' ? 44 : Number(clientColWidths[key] || 0);
        if (w > 40) col.style.width = `${w}px`;
        cg.appendChild(col);
      }
      updateSortIndicators();
    }
    function sortKeyFromHeader(th, fnName) {
      const onclick = String(th.getAttribute('onclick') || '');
      const match = onclick.match(new RegExp(`${fnName}\\('([^']+)'\\)`));
      return match ? match[1] : '';
    }
    function markSortedHeaders(tableId, fnName, activeKey, desc) {
      const table = byId(tableId);
      if (!table || !table.tHead) return;
      for (const th of Array.from(table.tHead.querySelectorAll('th'))) {
        const key = sortKeyFromHeader(th, fnName);
        const active = key && key === activeKey;
        th.classList.toggle('sort-active', active);
        th.classList.toggle('sort-desc', active && desc);
        th.classList.toggle('sort-asc', active && !desc);
        if (active) th.setAttribute('aria-sort', desc ? 'descending' : 'ascending');
        else th.removeAttribute('aria-sort');
      }
    }
    function updateSortIndicators() {
      markSortedHeaders('clientsTable', 'setSort', sortKey, sortDesc);
      markSortedHeaders('interfacesTable', 'setIfSort', ifSortKey, ifSortDesc);
    }
    function setupClientTableInteractions() {
      const table = byId('clientsTable');
      if (!table || !table.tHead || !table.tHead.rows.length) return;
      const headers = Array.from(table.tHead.rows[0].cells);
      for (const th of headers) {
        const key = th.dataset.col || '';
        if (!key) continue;
        if (key !== 'sel' && !th.querySelector('.resize-handle')) {
          const handle = document.createElement('span');
          handle.className = 'resize-handle';
          handle.addEventListener('mousedown', (ev) => {
            ev.preventDefault();
            ev.stopPropagation();
            const startX = ev.clientX;
            const startW = th.getBoundingClientRect().width;
            const onMove = (mv) => {
              const w = Math.max(58, Math.round(startW + (mv.clientX - startX)));
              clientColWidths[key] = w;
              applyClientColsLayout();
            };
            const onUp = () => {
              window.removeEventListener('mousemove', onMove);
              window.removeEventListener('mouseup', onUp);
              saveClientColsState();
            };
            window.addEventListener('mousemove', onMove);
            window.addEventListener('mouseup', onUp);
          });
          th.appendChild(handle);
        }
        th.draggable = key !== 'sel';
        th.addEventListener('dragstart', () => {
          if (key === 'sel') return;
          clientDraggingKey = key;
        });
        th.addEventListener('dragover', (ev) => {
          if (key === 'sel') return;
          ev.preventDefault();
          th.classList.add('drag-over');
        });
        th.addEventListener('dragleave', () => th.classList.remove('drag-over'));
        th.addEventListener('drop', (ev) => {
          ev.preventDefault();
          th.classList.remove('drag-over');
          const toKey = key;
          const fromKey = clientDraggingKey;
          if (toKey === 'sel' || fromKey === 'sel') return;
          if (!fromKey || !toKey || fromKey === toKey) return;
          const from = clientColOrder.indexOf(fromKey);
          const to = clientColOrder.indexOf(toKey);
          if (from < 0 || to < 0) return;
          clientColOrder.splice(from, 1);
          clientColOrder.splice(to, 0, fromKey);
          applyClientColsLayout();
          saveClientColsState();
        });
      }
      loadClientColsState();
      ensureClientColsOrder();
      if (!Object.keys(clientColWidths).length) {
        for (const th of headers) {
          const key = th.dataset.col || '';
          if (!key) continue;
          clientColWidths[key] = key === 'sel' ? 44 : Math.round(th.getBoundingClientRect().width);
        }
      }
      applyClientColsLayout();
      saveClientColsState();
    }

    async function api(path, options = {}) {
      const { timeoutMs = 10000, headers = {}, ...rest } = options;
      const ctl = new AbortController();
      const timer = setTimeout(() => ctl.abort(), timeoutMs);
      let resp;
      setUiBusy(true);
      try {
        resp = await fetch(path, {
          headers: { 'Content-Type': 'application/json', ...headers },
          signal: ctl.signal,
          ...rest,
        });
      } catch (e) {
        clearTimeout(timer);
        setUiBusy(false);
        if (e && e.name === 'AbortError') throw new Error(`Request timeout for ${path}`);
        throw e;
      }
      clearTimeout(timer);
      try {
        if (!resp.ok) {
          let detail = resp.statusText;
          try { detail = (await resp.json()).detail || detail; } catch (_) {}
          throw new Error(detail);
        }
        const ct = resp.headers.get('content-type') || '';
        if (ct.includes('application/json')) return resp.json();
        return resp.blob();
      } finally {
        setUiBusy(false);
      }
    }

    function setStatus(msg, bad = false) {
      const el = byId('statusBar');
      el.textContent = `status: ${msg}`;
      el.className = `pill ${bad ? 'bad' : (uiBusyCount > 0 ? 'busy' : 'meta')}`;
    }

    function setSort(key) {
      if (sortKey === key) sortDesc = !sortDesc;
      else { sortKey = key; sortDesc = false; }
      updateSortIndicators();
      savePanelSettingsDebounced();
      renderClients();
    }
    function toggleGroupCollapsed(groupId) {
      const gid = String(groupId || '').trim();
      if (!gid) return;
      if (collapsedGroupIds.has(gid)) collapsedGroupIds.delete(gid);
      else collapsedGroupIds.add(gid);
      saveGroupCollapseState();
      renderClients();
    }
    function collapseAllGroups() {
      groupsCache.forEach((g) => {
        const gid = String(g.id || '').trim();
        if (gid) collapsedGroupIds.add(gid);
      });
      saveGroupCollapseState();
      renderClients();
    }
    function expandAllGroups() {
      collapsedGroupIds.clear();
      saveGroupCollapseState();
      renderClients();
    }
    function toggleClientsFullscreen() {
      byId('clientsPanel')?.classList.toggle('panel-fullscreen');
      document.body.classList.toggle('clients-fullscreen-open', byId('clientsPanel')?.classList.contains('panel-fullscreen'));
    }
    function refreshBatchCount() {
      const el = byId('batchCount');
      if (el) el.textContent = `${selectedBatch.size} selected`;
      refreshActionsModal();
    }
    function setIfSort(key) {
      if (ifSortKey === key) ifSortDesc = !ifSortDesc;
      else {
        ifSortKey = key;
        // For numeric bandwidth/usage columns, descending is usually more useful.
        ifSortDesc = ['rx_bps', 'tx_bps', 'combined_bps', 'window_usage_bytes'].includes(key);
      }
      updateSortIndicators();
      savePanelSettingsDebounced();
      loadInterfaceStats();
    }

    function selectedRows() {
      return Array.from(selectedBatch);
    }

    function setActionButtonsState(mode, rows = []) {
      const isNone = mode === 'none';
      const isBatch = mode === 'batch';
      const hasGroupMember = (rows || []).some(clientIsGroupMember);
      const allButtons = [
        'btnActionEnable', 'btnActionDisable', 'btnActionReset', 'btnActionClear',
        'btnActionRevoke', 'btnActionDelete', 'btnActionSetSpeed', 'btnActionSetPolicy'
      ];
      const singleOnly = ['btnActionRevoke'];
      for (const id of allButtons) {
        const el = byId(id);
        if (el) el.disabled = isNone;
      }
      for (const id of singleOnly) {
        const el = byId(id);
        if (el) el.disabled = isNone || isBatch;
      }
      const clearBtn = byId('btnActionClear');
      if (clearBtn) clearBtn.style.display = hasGroupMember ? 'none' : '';
      for (const selector of ['.speed-row', '.policy-row']) {
        const el = document.querySelector(`#actionsModal ${selector}`);
        if (el) el.style.display = hasGroupMember ? 'none' : '';
      }
      const revokeBtn = byId('btnActionRevoke');
      if (revokeBtn) revokeBtn.style.display = isBatch ? 'none' : '';
      updateActionsConfigVisibility(mode);
    }
    function clientIsGroupMember(c) {
      if (!c) return false;
      if (Array.isArray(c.groups) && c.groups.length > 0) return true;
      return String(c.group_names || '').trim().length > 0;
    }

    function actionPeerIds() {
      if (actionsForcePeerId) return [actionsForcePeerId];
      // Always prefer explicit checkbox selection over highlighted row.
      const body = byId('clientsBody');
      if (body) {
        const checked = [];
        for (const tr of Array.from(body.querySelectorAll('tr'))) {
          const pid = tr.dataset.peerId || '';
          const cb = tr.querySelector('input[type="checkbox"]');
          if (pid && cb && cb.checked) checked.push(pid);
        }
        if (checked.length > 0) {
          selectedBatch.clear();
          for (const pid of checked) selectedBatch.add(pid);
          return checked;
        }
      }
      const ids = selectedRows();
      if (ids.length > 0) return ids;
      if (selectedPeerId) return [selectedPeerId];
      return [];
    }

    function refreshActionsModal() {
      const ids = actionPeerIds();
      const rows = ids.map((id) => clientById(id)).filter(Boolean);
      const list = byId('actionsSelectedList');
      if (!rows.length) {
        byId('selectedPeer').textContent = 'none';
        byId('actionsMode').textContent = 'mode: none';
        list.innerHTML = '<div class="meta">No client selected.</div>';
        renderActionsUserGraphs([]);
        if (!actionDraftDirty) {
          resetActionsDraftInputs();
          byId('configOut').value = '';
          configForPeerId = null;
          hasGeneratedConfig = false;
        }
        setActionButtonsState('none', []);
        return;
      }
      byId('selectedPeer').textContent = rows.length === 1 ? `${txt(rows[0].name)} (${rows[0].peer_id})` : `${rows.length} clients`;
      const mode = rows.length === 1 ? 'single' : 'batch';
      const groupedCount = rows.filter(clientIsGroupMember).length;
      byId('actionsMode').textContent = groupedCount ? `mode: ${mode} | ${groupedCount} group member(s): individual limits blocked` : `mode: ${mode}`;
      setActionButtonsState(mode, rows);
      list.innerHTML = `
        <div class="table-wrap" style="max-height:180px;">
          <table>
            <thead><tr><th>Comment</th><th>Interface</th><th>IP</th></tr></thead>
            <tbody>
              ${rows.map((r) => `<tr><td>${txt(r.name)}</td><td>${txt(r.interface)}</td><td>${txt(r.ip)}</td></tr>`).join('')}
            </tbody>
          </table>
        </div>
      `;
      renderActionsUserGraphs(rows);

      if (actionDraftDirty) {
        return;
      }

      if (rows.length === 1) {
        const c = rows[0];
        byId('spDown').value = c.speed_limit_down_bps > 0 ? fmtFormNumber(Number(c.speed_limit_down_bps) / 1_000_000) : '';
        byId('spUp').value = c.speed_limit_up_bps > 0 ? fmtFormNumber(Number(c.speed_limit_up_bps) / 1_000_000) : '';
        byId('plDown').value = c.traffic_limit_down_bytes > 0 ? fmtFormNumber(Number(c.traffic_limit_down_bytes) / (1024 * 1024 * 1024)) : '';
        byId('plUp').value = c.traffic_limit_up_bytes > 0 ? fmtFormNumber(Number(c.traffic_limit_up_bytes) / (1024 * 1024 * 1024)) : '';
        byId('plPeriod').value = periodInputFromSeconds(c.traffic_period_seconds);
        byId('plMode').value = (c.overlimit_mode || 'disable');
        byId('plOverDown').value = c.overlimit_speed_down_bps > 0 ? fmtFormNumber(Number(c.overlimit_speed_down_bps) / 1_000_000) : '';
        byId('plOverUp').value = c.overlimit_speed_up_bps > 0 ? fmtFormNumber(Number(c.overlimit_speed_up_bps) / 1_000_000) : '';
        if (configForPeerId && configForPeerId !== c.peer_id) {
          byId('configOut').value = '';
          configForPeerId = null;
          hasGeneratedConfig = false;
        }
      } else {
        resetActionsDraftInputs();
        byId('configOut').value = '';
        configForPeerId = null;
        hasGeneratedConfig = false;
      }
    }

    function selectPeer(peerId) {
      selectedPeerId = peerId;
      actionDraftDirty = false;
      const c = clientById(peerId);
      byId('selectedPeer').textContent = c ? `${txt(c.name)} (${peerId})` : peerId;
      refreshActionsModal();
      updateClientSelectionHighlight();
    }
    function openActionsForPeer(peerId) {
      selectedBatch.clear();
      selectPeer(peerId);
      actionsForcePeerId = peerId;
      const m = byId('actionsModal');
      if (m) m.classList.add('show');
      refreshActionsModal();
    }

    function renderClients() {
      let rows = [...clientsCache];
      const q = val('searchBox').toLowerCase();
      const filter = byId('clientFilter')?.value || 'all';
      rows = rows.filter((c) => clientMatchesFilter(c, filter));
      const rowById = new Map(rows.map((c) => [c.peer_id, c]));
      rows.sort(compareClientRows);

      const body = byId('clientsBody');
      body.innerHTML = '';
      byId('clientsCount').textContent = `${rows.length} users | ${groupsCache.length} groups | selected: ${selectedBatch.size} | sort: ${sortKey} ${sortDesc ? 'desc' : 'asc'}`;
      refreshBatchCount();

      function appendRow(c, opts = {}) {
        const tr = document.createElement('tr');
        if (!c.is_group_row) tr.dataset.peerId = c.peer_id;
        if (c.is_group_row) tr.dataset.groupId = c.group_id;
        const downLim = Number(c.traffic_limit_down_bytes || 0);
        const upLim = Number(c.traffic_limit_up_bytes || 0);
        const downUsed = Number(c.download_since_now_bytes || 0);
        const upUsed = Number(c.upload_since_now_bytes || 0);
        const quotaReached = (downLim > 0 && downUsed >= downLim) || (upLim > 0 && upUsed >= upLim);
        const downCap = Number(c.speed_limit_down_bps || 0);
        const upCap = Number(c.speed_limit_up_bps || 0);
        const nearSpeedCap = (downCap > 0 && Number(c.down_speed_bps || 0) >= downCap * 0.92)
          || (upCap > 0 && Number(c.up_speed_bps || 0) >= upCap * 0.92);
        const limited = Boolean(c.overlimit_active) || quotaReached || nearSpeedCap || Number(c.limit_conflict_count || 0) > 0;
        tr.className = `${c.is_group_row ? 'group-summary ' : ''}${opts.member ? 'group-member ' : ''}${selectedPeerId === c.peer_id ? 'selected ' : ''}${limited ? 'limited ' : ''}${c.state === 'disabled' ? 'disabled' : ''}`;
        if (c.is_group_row) {
          tr.onclick = () => toggleGroupCollapsed(c.group_id);
          tr.ondblclick = () => openGroupEditor(c.group_id);
        } else {
          tr.onclick = () => selectPeer(c.peer_id);
          tr.ondblclick = () => openActionsForPeer(c.peer_id);
        }
        const checked = !c.is_group_row && selectedBatch.has(c.peer_id) ? 'checked' : '';
        const memberGroup = opts.group || null;
        const quotaPct = memberGroup && !c.is_group_row ? memberGroupQuotaPct(c, memberGroup) : clientQuotaPct(c);
        const speedPct = memberGroup && !c.is_group_row ? memberGroupSpeedPct(c, memberGroup) : clientSpeedPct(c);
        const collapsed = c.is_group_row && collapsedGroupIds.has(c.group_id);
        const groupNameHtml = c.is_group_row
          ? `<button class="ghost compact group-toggle" title="${collapsed ? 'Expand group' : 'Collapse group'}" onclick="event.stopPropagation();toggleGroupCollapsed('${c.group_id}')">${collapsed ? '+' : '-'}</button><button class="link-button" title="Open group editor" onclick="event.stopPropagation();openGroupEditor('${c.group_id}')">${txt(c.name)}</button>`
          : `${opts.member ? '- ' : ''}${txt(c.name)}`;
        tr.innerHTML = `
          <td data-col="sel">${c.is_group_row ? '' : `<input type="checkbox" ${checked} onclick="event.stopPropagation();toggleBatch('${c.peer_id}', this.checked)" />`}</td>
          <td data-col="name">${groupNameHtml}</td>
          <td data-col="groups">${txt(c.group_names)}</td>
          <td data-col="effective">${effectiveLimitText(c)}</td>
          <td data-col="ip">${txt(c.ip)}</td>
          <td data-col="interface">${txt(c.interface)}</td>
          <td data-col="state">${txt(c.state)}</td>
          <td data-col="down">${txt(c.download_since_now)}</td>
          <td data-col="up">${txt(c.upload_since_now)}</td>
          <td data-col="dspd">${txt(c.down_speed)}</td>
          <td data-col="uspd">${txt(c.up_speed)}</td>
          <td data-col="dlim">${c.traffic_limit_down_bytes > 0 ? hBytes(c.traffic_limit_down_bytes) : 'not set'}</td>
          <td data-col="ulim">${c.traffic_limit_up_bytes > 0 ? hBytes(c.traffic_limit_up_bytes) : 'not set'}</td>
          <td data-col="period">${hPeriod(c.traffic_period_seconds)}</td>
          <td data-col="omode">${txt(c.overlimit_mode)}</td>
          <td data-col="odown">${c.overlimit_speed_down_bps > 0 ? hBps(c.overlimit_speed_down_bps) : 'not set'}</td>
          <td data-col="oup">${c.overlimit_speed_up_bps > 0 ? hBps(c.overlimit_speed_up_bps) : 'not set'}</td>
          <td data-col="oact">${c.overlimit_active ? 'yes' : 'no'}</td>
          <td data-col="slimd">${c.speed_limit_down_bps > 0 ? hBps(c.speed_limit_down_bps) : 'not set'}</td>
          <td data-col="slimu">${c.speed_limit_up_bps > 0 ? hBps(c.speed_limit_up_bps) : 'not set'}</td>
          <td data-col="qpct">${miniBarHtml(quotaPct)}</td>
          <td data-col="spct">${miniBarHtml(speedPct)}</td>
        `;
        body.appendChild(tr);
      }

      const assigned = new Set();
      const groupBlocks = [];
      for (const group of groupsCache) {
        const groupMatches = q && groupSearchText(group).includes(q);
        let members = (group.peer_ids || []).map((pid) => rowById.get(pid)).filter(Boolean);
        if (q && !groupMatches) members = members.filter((c) => clientSearchText(c).includes(q));
        if (!members.length) continue;
        members.sort(compareClientRows);
        groupBlocks.push({ group, members, summary: buildGroupSummaryRow(group, members) });
      }
      groupBlocks.sort((a, b) => compareClientRows(a.summary, b.summary));
      for (const block of groupBlocks) {
        appendRow(block.summary);
        for (const member of block.members) assigned.add(member.peer_id);
        if (collapsedGroupIds.has(block.group.id)) continue;
        for (const member of block.members) appendRow(member, { member: true, group: block.group });
      }

      for (const c of rows) {
        if (assigned.has(c.peer_id)) continue;
        if (q && !clientSearchText(c).includes(q)) continue;
        appendRow(c);
      }
      applyClientColsLayout();
      updateClientSelectionHighlight();
    }

    function updateClientSelectionHighlight() {
      const body = byId('clientsBody');
      if (!body) return;
      for (const tr of Array.from(body.querySelectorAll('tr'))) {
        const pid = tr.dataset.peerId || '';
        if (pid && pid === selectedPeerId) tr.classList.add('selected');
        else tr.classList.remove('selected');
      }
    }

    function toggleBatch(peerId, checked) {
      if (checked) selectedBatch.add(peerId);
      else selectedBatch.delete(peerId);
      byId('clientsCount').textContent = `${clientsCache.length} users | selected: ${selectedBatch.size} | sort: ${sortKey} ${sortDesc ? 'desc' : 'asc'}`;
      refreshBatchCount();
    }

    function clearBatch() {
      selectedBatch.clear();
      renderClients();
    }

    function selectAllVisible() {
      const q = val('searchBox').toLowerCase();
      const filter = byId('clientFilter')?.value || 'all';
      let rows = [...clientsCache];
      if (q) rows = rows.filter(c => (`${txt(c.name)} ${txt(c.group_names)} ${effectiveLimitText(c)} ${txt(c.ip)} ${txt(c.interface)} ${txt(c.peer_id)}`).toLowerCase().includes(q));
      rows = rows.filter((c) => clientMatchesFilter(c, filter));
      for (const c of rows) selectedBatch.add(c.peer_id);
      renderClients();
    }
