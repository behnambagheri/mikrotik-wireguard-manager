    function renderOverview(data) {
      const rr = data.resource || {};
      const cpu = Number(rr['cpu-load'] || 0);
      const tm = Number(rr['total-memory'] || 0);
      const fm = Number(rr['free-memory'] || 0);
      const memPct = tm > 0 ? ((tm - fm) * 100 / tm) : 0;
      const th = Number(rr['total-hdd-space'] || 0);
      const fh = Number(rr['free-hdd-space'] || 0);
      const diskPct = th > 0 ? ((th - fh) * 100 / th) : 0;

      byId('cpuVal').innerHTML = `<span class="kpi-main">${cpu.toFixed(1)}%</span>`;
      byId('memVal').innerHTML = `<span class="kpi-main">${memPct.toFixed(1)}%</span><span class="kpi-detail">${esc(hBytes(tm - fm))} / ${esc(hBytes(tm))}</span>`;
      byId('diskVal').innerHTML = `<span class="kpi-main">${diskPct.toFixed(1)}%</span><span class="kpi-detail">${esc(hBytes(th - fh))} / ${esc(hBytes(th))}</span>`;
      byId('bwVal').innerHTML = `
        <span class="bw-line"><span class="bw-label">RX</span><span class="bw-value">${esc(hBytes(data.bandwidth_bps.rx))}/s</span></span>
        <span class="bw-line"><span class="bw-label">TX</span><span class="bw-value">${esc(hBytes(data.bandwidth_bps.tx))}/s</span></span>
      `;
      byId('cpuBar').style.width = `${Math.max(0, Math.min(100, cpu))}%`;
      byId('memBar').style.width = `${Math.max(0, Math.min(100, memPct))}%`;
      byId('diskBar').style.width = `${Math.max(0, Math.min(100, diskPct))}%`;

      byId('overviewLine').innerHTML = [
        `<span class="overview-chip"><strong>Router</strong> ${esc(data.profile)}@${esc(data.router)}</span>`,
        `<span class="overview-chip"><strong>Version</strong> ${esc(rr.version)}</span>`,
        `<span class="overview-chip"><strong>Uptime</strong> ${esc(rr.uptime)}</span>`,
        `<span class="overview-chip"><strong>Poll</strong> ${Math.round(data.poll_latency_ms)}ms</span>`,
      ].join('');
      const alertsEl = byId('alerts');
      if ((data.alerts || []).length) {
        alertsEl.innerHTML = '';
        (data.alerts || []).forEach((a, idx) => {
          const text = String(a || '');
          const isStale = text.startsWith('Stale handshake peers (>10m):');
          const span = document.createElement('span');
          span.className = isStale ? 'warn clickable' : 'warn';
          span.textContent = text;
          if (isStale) {
            span.title = 'Click to see stale peers';
            span.onclick = openStaleModal;
          }
          alertsEl.appendChild(span);
          if (idx < (data.alerts || []).length - 1) {
            const sep = document.createElement('span');
            sep.className = 'meta';
            sep.textContent = ' | ';
            alertsEl.appendChild(sep);
          }
        });
      } else {
        alertsEl.innerHTML = '<span class="ok">No alerts</span>';
      }
      renderWgHealth(data.wg_health || []);
    }

    async function loadOverview(options = {}) {
      const data = await api('/api/overview');
      if (!isCurrentRouterDataEpoch(options.epoch)) return;
      renderOverview(data);
    }

    function renderInterfaceStats(items) {
      let rows = [...(items || [])];
      rows.sort((a, b) => {
        const av = a[ifSortKey];
        const bv = b[ifSortKey];
        const dir = ifSortDesc ? -1 : 1;
        if (typeof av === 'number' && typeof bv === 'number') {
          return (av - bv) * dir;
        }
        const aa = txt(av).toLowerCase();
        const bb = txt(bv).toLowerCase();
        if (aa < bb) return -1 * dir;
        if (aa > bb) return 1 * dir;
        return 0;
      });
      const body = byId('ifStatsBody');
      body.innerHTML = '';
      for (const i of rows) {
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td>${txt(i.name)}</td>
          <td>${txt(i.type)}</td>
          <td>${txt(i.running)}</td>
          <td>${txt(i.rx_h)}</td>
          <td>${txt(i.tx_h)}</td>
          <td>${hBytes(i.combined_bps)}/s</td>
          <td>${txt(i.window_usage_h)}</td>
        `;
        body.appendChild(tr);
      }
      updateSortIndicators();
    }

    async function loadInterfaceStats(options = {}) {
      const data = await api('/api/interfaces/stats');
      if (!isCurrentRouterDataEpoch(options.epoch)) return;
      renderInterfaceStats(data.items || []);
    }

    async function renderInterfaces(items, options = {}) {
      const refreshPool = options.refreshPool !== false;
      const sel = byId('addIface');
      const previous = sel.value;
      sel.innerHTML = '';
      for (const i of items || []) {
        const o = document.createElement('option');
        o.value = i.name;
        o.textContent = `${i.name} (listen:${i.listen_port || '?'})`;
        sel.appendChild(o);
      }
      if (previous && Array.from(sel.options).some((o) => o.value === previous)) {
        sel.value = previous;
      }
      bindAddFormValidation();
      if (refreshPool && sel.value) await loadAddIfacePoolInfo(sel.value);
    }

    async function loadInterfaces(options = {}) {
      const data = await api('/api/interfaces');
      if (!isCurrentRouterDataEpoch(options.epoch)) return;
      await renderInterfaces(data.items || []);
    }

    function renderClientData(items) {
      clientsCache = items || [];
      if (!groupsCache.length && typeof deriveGroupsFromClients === 'function') {
        const derivedGroups = deriveGroupsFromClients(clientsCache);
        if (derivedGroups.length) {
          groupsCache = derivedGroups;
          renderGroups();
        }
      }
      renderSnapshotCharts(clientsCache);
      const exists = new Set(clientsCache.map(x => x.peer_id));
      for (const pid of Array.from(selectedBatch)) {
        if (!exists.has(pid)) selectedBatch.delete(pid);
      }
      renderClients();
      if (selectedPeerId) {
        const c = clientsCache.find(x => x.peer_id === selectedPeerId) || null;
        refreshActionsModal();
        if (!c) {
          byId('selectedPeer').textContent = 'none';
          selectedPeerId = null;
        }
      } else {
        refreshActionsModal();
      }
      if (groupEditorId) renderGroupEditor();
    }

    async function loadClients(options = {}) {
      const data = await api('/api/clients');
      if (!isCurrentRouterDataEpoch(options.epoch)) return;
      renderClientData(data.items || []);
    }

    async function applyLiveSnapshot(snapshot) {
      if (!snapshot || snapshot.status === 'error') {
        setStatus(snapshot && snapshot.detail ? snapshot.detail : 'live update failed', true);
        return;
      }
      const epoch = routerDataEpoch;
      renderOverview(snapshot.overview || {});
      renderInterfaceStats(snapshot.interfaces || []);
      await renderInterfaces(snapshot.wireguard_interfaces || [], { refreshPool: false });
      if (!isCurrentRouterDataEpoch(epoch)) return;
      renderGroupData(snapshot.groups || []);
      renderClientData(snapshot.clients || []);
      setStatus(snapshot.status === 'busy' ? 'live update skipped: manager busy' : 'live update received');
    }

    async function runDiagnostics() {
      try {
        const data = await api('/api/diagnostics');
        const body = byId('diagBody');
        body.innerHTML = '';
        for (const d of data.items || []) {
          const cls = d.status === 'ok' ? 'diag-ok' : 'diag-bad';
          const tr = document.createElement('tr');
          tr.innerHTML = `<td>${txt(d.profile)}</td><td>${txt(d.router_ip)}</td><td class="${cls}">${txt(d.status)}</td><td>${txt(d.ports)}</td><td>${txt(d.detail)}</td>`;
          body.appendChild(tr);
        }
        setStatus('diagnostics updated');
      } catch (e) { setStatus(e.message, true); }
    }
