let selectedPeerId = null;
      let clientsCache = [];
      let groupsCache = [];
      let groupEditorId = null;
      let groupEditorShowAll = false;
      let sortKey = 'name';
    let sortDesc = false;
    let ifSortKey = 'combined_bps';
    let ifSortDesc = true;
    let liveSource = null;
    let liveFallbackTimer = null;
    let lastConfigFilename = 'client.conf';
    let configForPeerId = null;
    let hasGeneratedConfig = false;
    const selectedBatch = new Set();
    const THEME_KEY = 'wg_web_theme';
    const CLIENT_COLS_KEY = 'wg_clients_cols_v5';
    const GROUP_COLLAPSED_KEY = 'wg_group_collapsed_v1';
    const DEFAULT_CLIENT_COL_ORDER = [
      'sel', 'name', 'ip', 'dspd', 'uspd', 'qpct', 'spct', 'oact', 'period',
      'up', 'down', 'slimd', 'slimu', 'dlim', 'ulim', 'omode', 'odown', 'oup', 'state', 'interface', 'effective', 'groups',
    ];
    let clientColOrder = [];
    let clientColWidths = {};
    let clientDraggingKey = null;
    let actionsForcePeerId = null;
    const addIfacePoolCache = new Map();
    let profileManagerRows = [];
    let profileManagerEditName = null;
    let refreshInFlight = null;
    let uiBusyCount = 0;
    let authStatusCache = null;
    let actionDraftDirty = false;
    let groupDraftDirty = false;
    const collapsedGroupIds = new Set();
    let panelSettings = {};
    let panelSettingsTimer = null;
    let routerDataEpoch = 0;
    const PANEL_SECTION_KEYS = ['dashboard', 'diagnostics', 'wg_health', 'router_pulse', 'snapshots', 'groups', 'clients'];

    function txt(v) { return (v === null || v === undefined || v === '') ? 'not set' : String(v); }
    function esc(v) {
      return txt(v).replace(/[&<>"']/g, (ch) => ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;',
      }[ch]));
    }
    function val(id) { return document.getElementById(id).value.trim(); }
    function numOrNull(id) { const v = val(id); return v === '' ? null : Number(v); }
    function num(id) { const v = val(id); return v === '' ? 0 : Number(v); }
    function byId(id) { return document.getElementById(id); }
    function updateBusyControls() {
      const busy = uiBusyCount > 0;
      document.body.setAttribute('data-busy', busy ? 'true' : 'false');
      document.querySelectorAll('button, select, input, textarea').forEach((el) => {
        if (el.dataset.busyAllow === '1') return;
        if (busy) {
          if (!Object.prototype.hasOwnProperty.call(el.dataset, 'busyPrevDisabled')) {
            el.dataset.busyPrevDisabled = el.disabled ? '1' : '0';
          }
          el.disabled = true;
          return;
        }
        if (Object.prototype.hasOwnProperty.call(el.dataset, 'busyPrevDisabled')) {
          el.disabled = el.dataset.busyPrevDisabled === '1';
          delete el.dataset.busyPrevDisabled;
        }
      });
    }
    function setUiBusy(active) {
      if (active) uiBusyCount += 1;
      else uiBusyCount = Math.max(0, uiBusyCount - 1);
      updateBusyControls();
    }
    function sanitizeSearchInput() {
      const el = byId('searchBox');
      if (!el) return;
      el.value = (el.value || '').replace(/[^A-Za-z0-9.\-_\u0640 ]/g, '');
    }
    function sanitizeGroupNameInput() {
      const el = byId('groupName');
      if (!el) return;
      el.value = String(el.value || '').replace(/[^A-Za-z0-9 _.-]/g, '').slice(0, 64);
    }
    function sanitizeEnglishNumberInput(id) {
      const el = byId(id);
      if (!el) return;
      let v = String(el.value || '');
      v = v.replace(/[^0-9.]/g, '');
      const firstDot = v.indexOf('.');
      if (firstDot >= 0) v = v.slice(0, firstDot + 1) + v.slice(firstDot + 1).replace(/\./g, '');
      el.value = v.slice(0, 16);
    }
    function sanitizeIpv4Input(id) {
      const el = byId(id);
      if (!el) return;
      let v = String(el.value || '').replace(/[^0-9.]/g, '');
      v = v.replace(/\.{2,}/g, '.');
      el.value = v.slice(0, 15);
    }
    function sanitizeCommentInput() {
      const el = byId('addComment');
      if (!el) return;
      el.value = String(el.value || '').replace(/[^A-Za-z0-9 -]/g, '').slice(0, 32);
    }
    function sanitizePeriodInput() {
      const el = byId('addPeriod');
      if (!el) return;
      el.value = String(el.value || '').replace(/[^A-Za-z0-9.]/g, '').slice(0, 16);
    }
    function validPeriodText(s) {
      const t = String(s || '').trim().toLowerCase();
      if (!t) return true;
      if (['0', 'none', 'off', 'hour', 'day', 'week', '1h', '1d', '1w', 'h', 'd', 'w'].includes(t)) return true;
      return /^([0-9]+(\.[0-9]+)?)([smhdw]?)$/.test(t);
    }
    function ipv4ToInt(s) {
      const parts = String(s || '').split('.');
      if (parts.length !== 4) return null;
      let n = 0;
      for (const p of parts) {
        if (!/^\d+$/.test(p)) return null;
        const v = Number(p);
        if (!Number.isInteger(v) || v < 0 || v > 255) return null;
        n = (n << 8) + v;
      }
      return n >>> 0;
    }
    function ipInCidr(ip, cidr) {
      const m = String(cidr || '').split('/');
      if (m.length !== 2) return false;
      const base = ipv4ToInt(m[0]);
      const bits = Number(m[1]);
      const cur = ipv4ToInt(ip);
      if (base === null || cur === null || !Number.isInteger(bits) || bits < 0 || bits > 32) return false;
      const mask = bits === 0 ? 0 : ((0xffffffff << (32 - bits)) >>> 0);
      return ((base & mask) >>> 0) === ((cur & mask) >>> 0);
    }
    async function loadAddIfacePoolInfo(iface) {
      const key = String(iface || '').trim();
      if (!key) return null;
      if (addIfacePoolCache.has(key)) return addIfacePoolCache.get(key);
      try {
        const info = await api(`/api/interfaces/${encodeURIComponent(key)}/ip-pool`);
        addIfacePoolCache.set(key, info);
        return info;
      } catch (_) {
        return null;
      }
    }
    function bindAddFormValidation() {
      const numericIds = ['addSpeedDown', 'addSpeedUp', 'addLimitDown', 'addLimitUp', 'addOverDown', 'addOverUp'];
      for (const id of numericIds) {
        const el = byId(id);
        if (el && !el.dataset.vBound) {
          el.dataset.vBound = '1';
          el.addEventListener('input', () => sanitizeEnglishNumberInput(id));
        }
      }
      const ipEl = byId('addIp');
      if (ipEl && !ipEl.dataset.vBound) {
        ipEl.dataset.vBound = '1';
        ipEl.addEventListener('input', () => sanitizeIpv4Input('addIp'));
      }
      const cEl = byId('addComment');
      if (cEl && !cEl.dataset.vBound) {
        cEl.dataset.vBound = '1';
        cEl.addEventListener('input', sanitizeCommentInput);
      }
      const pEl = byId('addPeriod');
      if (pEl && !pEl.dataset.vBound) {
        pEl.dataset.vBound = '1';
        pEl.addEventListener('input', sanitizePeriodInput);
      }
      const ifaceEl = byId('addIface');
      if (ifaceEl && !ifaceEl.dataset.vBound) {
        ifaceEl.dataset.vBound = '1';
        ifaceEl.addEventListener('change', async () => { await loadAddIfacePoolInfo(ifaceEl.value); });
      }
    }
    function resetAddForm() {
      const ids = ['addIp', 'addComment', 'addSpeedDown', 'addSpeedUp', 'addLimitDown', 'addLimitUp', 'addPeriod', 'addOverDown', 'addOverUp', 'addConfigOut'];
      for (const id of ids) {
        const el = byId(id);
        if (el) el.value = '';
      }
      const mode = byId('addMode');
      if (mode) mode.value = '';
    }
    function resetActionsDraftInputs() {
      const ids = ['spDown', 'spUp', 'plDown', 'plUp', 'plPeriod', 'plOverDown', 'plOverUp'];
      for (const id of ids) {
        const el = byId(id);
        if (el) el.value = '';
      }
      const mode = byId('plMode');
      if (mode) mode.value = 'disable';
    }
    function bindDraftDirtyTracking() {
      const actionIds = ['spDown', 'spUp', 'plDown', 'plUp', 'plPeriod', 'plMode', 'plOverDown', 'plOverUp'];
      for (const id of actionIds) {
        const el = byId(id);
        if (el && !el.dataset.dirtyBound) {
          el.dataset.dirtyBound = '1';
          el.addEventListener('input', () => { actionDraftDirty = true; });
          el.addEventListener('change', () => { actionDraftDirty = true; });
        }
      }
      const groupIds = ['groupSpeedDown', 'groupSpeedUp', 'groupLimitDown', 'groupLimitUp', 'groupPeriod', 'groupMode', 'groupOverDown', 'groupOverUp'];
      for (const id of groupIds) {
        const el = byId(id);
        if (el && !el.dataset.dirtyBound) {
          el.dataset.dirtyBound = '1';
          el.addEventListener('input', () => { groupDraftDirty = true; });
          el.addEventListener('change', () => { groupDraftDirty = true; });
        }
      }
    }
    function applyTheme(theme, persist = true) {
      const mode = theme === 'light' ? 'light' : 'dark';
      document.body.setAttribute('data-theme', mode);
      const btn = byId('themeBtn');
      if (btn) btn.textContent = mode === 'dark' ? 'Light' : 'Dark';
      if (persist) savePanelSettingsDebounced();
    }
    function initTheme() {
      let saved = panelSettings.theme || null;
      try { saved = saved || localStorage.getItem(THEME_KEY); } catch (_) {}
      if (saved === 'dark' || saved === 'light') {
        applyTheme(saved, false);
        return;
      }
      const prefersLight = window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches;
      applyTheme(prefersLight ? 'light' : 'dark', false);
    }
    function toggleTheme() {
      const now = document.body.getAttribute('data-theme') === 'light' ? 'light' : 'dark';
      const next = now === 'dark' ? 'light' : 'dark';
      applyTheme(next);
      try { localStorage.setItem(THEME_KEY, next); } catch (_) {}
    }
    function loadGroupCollapseState() {
      try {
        const ids = Array.isArray(panelSettings.collapsed_groups)
          ? panelSettings.collapsed_groups
          : JSON.parse(localStorage.getItem(GROUP_COLLAPSED_KEY) || '[]');
        collapsedGroupIds.clear();
        if (Array.isArray(ids)) ids.forEach((id) => {
          const clean = String(id || '').trim();
          if (clean) collapsedGroupIds.add(clean);
        });
      } catch (_) {
        collapsedGroupIds.clear();
      }
    }
    function saveGroupCollapseState() {
      try { localStorage.setItem(GROUP_COLLAPSED_KEY, JSON.stringify(Array.from(collapsedGroupIds))); } catch (_) {}
      savePanelSettingsDebounced();
    }
    function currentPanelSettings() {
      // Persist only UI preferences here; router policies remain enforced on RouterOS.
      return {
        theme: document.body.getAttribute('data-theme') === 'light' ? 'light' : 'dark',
        auto_refresh_seconds: Number(byId('autoSec')?.value || 0),
        client_filter: byId('clientFilter')?.value || 'all',
        client_sort_key: sortKey,
        client_sort_desc: Boolean(sortDesc),
        interface_sort_key: ifSortKey,
        interface_sort_desc: Boolean(ifSortDesc),
        client_columns: { order: clientColOrder, widths: clientColWidths },
        collapsed_groups: Array.from(collapsedGroupIds),
        groups_panel_collapsed: Boolean(byId('groupsList')?.classList.contains('collapsed')),
        visible_sections: Object.fromEntries(PANEL_SECTION_KEYS.map((key) => [key, !document.body.classList.contains(`hide-${key}`)])),
      };
    }
    function savePanelSettingsDebounced() {
      // Batch frequent UI changes such as column resizing so the state file is not
      // rewritten for every mouse movement.
      clearTimeout(panelSettingsTimer);
      panelSettingsTimer = setTimeout(async () => {
        try {
          panelSettings = currentPanelSettings();
          await api('/api/panel/settings', {
            method: 'POST',
            body: JSON.stringify({ settings: panelSettings }),
          });
        } catch (_) {}
      }, 300);
    }
    async function loadPanelSettings() {
      try {
        const out = await api('/api/panel/settings');
        panelSettings = out.settings || {};
      } catch (_) {
        panelSettings = {};
      }
    }
    function applyPanelSettingsToControls() {
      const auto = byId('autoSec');
      if (auto && panelSettings.auto_refresh_seconds !== undefined) auto.value = String(panelSettings.auto_refresh_seconds);
      const filter = byId('clientFilter');
      if (filter && panelSettings.client_filter) filter.value = panelSettings.client_filter;
      if (panelSettings.client_sort_key) sortKey = String(panelSettings.client_sort_key);
      if (panelSettings.client_sort_desc !== undefined) sortDesc = Boolean(panelSettings.client_sort_desc);
      if (panelSettings.interface_sort_key) ifSortKey = String(panelSettings.interface_sort_key);
      if (panelSettings.interface_sort_desc !== undefined) ifSortDesc = Boolean(panelSettings.interface_sort_desc);
      if (panelSettings.client_columns && typeof panelSettings.client_columns === 'object') {
        if (Array.isArray(panelSettings.client_columns.order)) clientColOrder = panelSettings.client_columns.order.map((x) => String(x || ''));
        if (panelSettings.client_columns.widths && typeof panelSettings.client_columns.widths === 'object') clientColWidths = panelSettings.client_columns.widths;
      }
      const visible = panelSettings.visible_sections || {};
      for (const key of PANEL_SECTION_KEYS) {
        setPanelSectionVisible(key, visible[key] !== false, false);
        const cb = byId(`sectionToggle_${key}`);
        if (cb) cb.checked = visible[key] !== false;
      }
      if (panelSettings.groups_panel_collapsed) byId('groupsList')?.classList.add('collapsed');
    }
    function setPanelSectionVisible(key, visible, persist = true) {
      document.body.classList.toggle(`hide-${key}`, !visible);
      if (persist) savePanelSettingsDebounced();
    }
    function nextRouterDataEpoch() {
      routerDataEpoch += 1;
      return routerDataEpoch;
    }
    function isCurrentRouterDataEpoch(epoch) {
      return epoch === undefined || epoch === routerDataEpoch;
    }
    function clearRouterScopedUiState() {
      selectedPeerId = null;
      selectedBatch.clear();
      clientsCache = [];
      groupsCache = [];
      groupEditorId = null;
      renderGroups();
      renderClientData([]);
      renderSnapshotCharts([]);
      refreshBatchCount();
    }
    function togglePanelSettingsMenu(ev) {
      if (ev) ev.stopPropagation();
      byId('panelSettingsMenu')?.classList.toggle('show');
    }
    function closePanelSettingsMenu() {
      byId('panelSettingsMenu')?.classList.remove('show');
    }
    function toggleGroupsPanelCollapsed() {
      byId('groupsList')?.classList.toggle('collapsed');
      savePanelSettingsDebounced();
    }
    function openModal(id) {
      const m = byId(id);
      if (id === 'addModal') {
        resetAddForm();
        bindAddFormValidation();
        loadAddIfacePoolInfo(byId('addIface')?.value || '');
      }
      if (id === 'actionsModal') {
        actionsForcePeerId = null;
        actionDraftDirty = false;
        refreshActionsModal();
      }
      if (m) m.classList.add('show');
    }
    function closeModal(id) {
      const m = byId(id);
      if (id === 'addModal') resetAddForm();
      if (id === 'actionsModal') {
        actionsForcePeerId = null;
        actionDraftDirty = false;
        resetActionsDraftInputs();
      }
      if (id === 'profileModal') {
        profileManagerEditName = null;
      }
      if (id === 'groupEditorModal') {
        groupEditorId = null;
        const search = byId('groupEditorSearch');
        if (search) search.value = '';
      }
      if (m) m.classList.remove('show');
    }
    function closeActionsMenu() {
      byId('actionsDdMenu')?.classList.remove('show');
    }
    function openActionsMenu(ev) {
      if (ev) ev.stopPropagation();
      refreshActionsMenuModal();
      const m = byId('actionsDdMenu');
      if (!m) return;
      m.classList.toggle('show');
    }
    function refreshActionsMenuModal() {
      const ids = actionPeerIds();
      const rows = ids.map((id) => clientsCache.find((x) => x.peer_id === id)).filter(Boolean);
      const hasGroupMember = rows.some(clientIsGroupMember);
      byId('actionsMenuCount').textContent = `${ids.length} selected`;
      byId('actionsMenuHint').textContent = ids.length === 0
        ? 'Select at least one client.'
        : (hasGroupMember ? 'Group member: individual limits are managed by the group.' : (ids.length === 1 ? 'Single-client actions available.' : 'Batch mode: Revoke is hidden.'));
      const revoke = byId('actionsMenuRevoke');
      if (revoke) revoke.style.display = ids.length === 1 ? '' : 'none';
      const clear = byId('actionsMenuClear');
      if (clear) clear.style.display = hasGroupMember ? 'none' : '';
    }
    function menuEdit() {
      closeActionsMenu();
      openModal('actionsModal');
      refreshActionsModal();
    }
    async function menuEnable() { closeActionsMenu(); await actionSetEnable(true); }
    async function menuDisable() { closeActionsMenu(); await actionSetEnable(false); }
    async function menuResetUsage() { closeActionsMenu(); await actionResetUsage(); }
    async function menuClearLimits() { closeActionsMenu(); await actionClearLimits(); }
    async function menuDelete() { closeActionsMenu(); await actionDelete(); }
    async function menuRevoke() { closeActionsMenu(); await actionRevoke(); }
    function updateActionsConfigVisibility(mode) {
      const cfg = byId('actionsConfigSection');
      const out = byId('configOut');
      if (!cfg || !out) return;
      const hasText = Boolean((out.value || '').trim());
      const visible = mode === 'single' && hasGeneratedConfig && hasText;
      cfg.style.display = visible ? '' : 'none';
    }
    function hBytes(n) {
      if (!n || n <= 0) return '0 B';
      const units = ['B','KB','MB','GB','TB'];
      let x = Number(n), i = 0;
      while (x >= 1024 && i < units.length - 1) { x /= 1024; i += 1; }
      if (i === 0) return `${Math.round(x)} ${units[i]}`;
      const s = x.toFixed(1).replace(/\.0$/, '');
      return `${s} ${units[i]}`;
    }
    function hBps(n) {
      const v = Number(n || 0);
      if (v <= 0) return '0 bps';
      const compact = (x) => x.toFixed(2).replace(/\.00$/, '').replace(/(\.\d)0$/, '$1');
      if (v >= 1_000_000_000) return `${compact(v / 1_000_000_000)} Gbps`;
      if (v >= 1_000_000) return `${compact(v / 1_000_000)} Mbps`;
      if (v >= 1_000) return `${compact(v / 1_000)} Kbps`;
      return `${Math.round(v)} bps`;
    }
    function hPeriod(sec) {
      const s = Number(sec || 0);
      if (s <= 0) return 'not set';
      if (s % 86400 === 0) {
        const d = s / 86400;
        return d === 1 ? '1 day' : `${d} days`;
      }
      if (s % 3600 === 0) {
        const h = s / 3600;
        return h === 1 ? '1 hour' : `${h} hours`;
      }
      if (s % 60 === 0) {
        const m = s / 60;
        return m === 1 ? '1 minute' : `${m} minutes`;
      }
      return `${s}s`;
    }
    function hDuration(sec) {
      const s0 = Math.max(0, Math.round(Number(sec || 0)));
      if (s0 <= 0) return '0s';
      let s = s0;
      const d = Math.floor(s / 86400);
      s -= d * 86400;
      const h = Math.floor(s / 3600);
      s -= h * 3600;
      const m = Math.floor(s / 60);
      s -= m * 60;
      const parts = [];
      if (d > 0) parts.push(`${d}d`);
      if (h > 0) parts.push(`${h}h`);
      if (m > 0 && parts.length < 2) parts.push(`${m}m`);
      if (s > 0 && parts.length < 2) parts.push(`${s}s`);
      return parts.join(' ');
    }
    function handshakeToSeconds(text) {
      const s = String(text || '').trim().toLowerCase();
      if (!s) return null;
      const re = /([0-9]+)\s*([wdhms])/g;
      let m = null;
      let sum = 0;
      let consumed = 0;
      while ((m = re.exec(s)) !== null) {
        const n = Number(m[1] || 0);
        const u = m[2];
        consumed += m[0].length;
        if (u === 'w') sum += n * 7 * 86400;
        else if (u === 'd') sum += n * 86400;
        else if (u === 'h') sum += n * 3600;
        else if (u === 'm') sum += n * 60;
        else if (u === 's') sum += n;
      }
      const compact = s.replace(/\s+/g, '');
      if (consumed <= 0 || consumed !== compact.length) return null;
      return sum;
    }
    function stalePeersFromCache() {
      const rows = Array.isArray(clientsCache) ? clientsCache : [];
      const stale = rows.filter((c) => {
        const hs = handshakeToSeconds(c.last_handshake);
        return hs !== null && hs > 600;
      });
      stale.sort((a, b) => {
        const aa = handshakeToSeconds(a.last_handshake) || 0;
        const bb = handshakeToSeconds(b.last_handshake) || 0;
        return bb - aa;
      });
      return stale;
    }
    function openStaleModal() {
      const rows = stalePeersFromCache();
      const body = byId('staleBody');
      if (!body) return;
      body.innerHTML = '';
      for (const c of rows) {
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td>${txt(c.name)}</td>
          <td>${txt(c.ip)}</td>
          <td>${txt(c.interface)}</td>
          <td>${txt(c.state)}</td>
          <td>${txt(c.last_handshake)}</td>
        `;
        body.appendChild(tr);
      }
      byId('staleCount').textContent = `${rows.length} peers`;
      openModal('staleModal');
    }
    function periodInputFromSeconds(sec) {
      const s = Number(sec || 0);
      if (s <= 0) return '';
      if (s % (7 * 86400) === 0) return `${s / (7 * 86400)}w`;
      if (s % 86400 === 0) return `${s / 86400}d`;
      if (s % 3600 === 0) return `${s / 3600}h`;
      if (s % 60 === 0) return `${s / 60}m`;
      return `${s}s`;
    }
    function fmtFormNumber(v) {
      const n = Number(v || 0);
      if (!Number.isFinite(n)) return '';
      const s = n.toFixed(2);
      return s.replace(/\.00$/, '').replace(/(\.\d)0$/, '$1');
    }
    function clientQuotaPct(c) {
      const dLim = Number(c.traffic_limit_down_bytes || 0);
      const uLim = Number(c.traffic_limit_up_bytes || 0);
      const dUsed = Number(c.download_since_now_bytes || 0);
      const uUsed = Number(c.upload_since_now_bytes || 0);
      const parts = [];
      if (dLim > 0) parts.push((dUsed / dLim) * 100);
      if (uLim > 0) parts.push((uUsed / uLim) * 100);
      if (!parts.length) return null;
      return Math.max(...parts);
    }
    function clientSpeedPct(c) {
      const dCap = Number(c.speed_limit_down_bps || 0);
      const uCap = Number(c.speed_limit_up_bps || 0);
      const dNow = Number(c.down_speed_bps || 0);
      const uNow = Number(c.up_speed_bps || 0);
      const parts = [];
      if (dCap > 0) parts.push((dNow / dCap) * 100);
      if (uCap > 0) parts.push((uNow / uCap) * 100);
      if (!parts.length) return null;
      return Math.max(...parts);
    }
    function memberGroupQuotaPct(c, group) {
      if (!c || !group) return null;
      const dLim = Number(group.traffic_limit_down_bytes || 0);
      const uLim = Number(group.traffic_limit_up_bytes || 0);
      const dUsed = Number(c.download_since_now_bytes || 0);
      const uUsed = Number(c.upload_since_now_bytes || 0);
      const parts = [];
      if (dLim > 0) parts.push((dUsed / dLim) * 100);
      if (uLim > 0) parts.push((uUsed / uLim) * 100);
      if (!parts.length) return null;
      return Math.max(...parts);
    }
    function memberGroupSpeedPct(c, group) {
      if (!c || !group) return null;
      const dCap = Number(group.speed_limit_down_bps || 0);
      const uCap = Number(group.speed_limit_up_bps || 0);
      const dNow = Number(c.down_speed_bps || 0);
      const uNow = Number(c.up_speed_bps || 0);
      const parts = [];
      if (dCap > 0) parts.push((dNow / dCap) * 100);
      if (uCap > 0) parts.push((uNow / uCap) * 100);
      if (!parts.length) return null;
      return Math.max(...parts);
    }
    function effectiveLimitText(c) {
      if (c && c.is_group_row) return 'group total';
      const parts = [];
      if (c.effective_speed_scope === 'group') parts.push(`speed: group ${txt(c.effective_speed_group_names)}`);
      else if (c.effective_speed_scope === 'individual') parts.push('speed: user');
      if (c.effective_policy_scope === 'group') parts.push(`policy: group ${txt(c.effective_policy_group_names)}`);
      else if (c.effective_policy_scope === 'individual') parts.push('policy: user');
      if (!parts.length) return 'none';
      if (Number(c.limit_conflict_count || 0) > 0) parts.push('override');
      return parts.join(' | ');
    }
    function groupSearchText(g) {
      const members = (g.members || []).map((m) => `${txt(m.name)} ${txt(m.ip)} ${txt(m.interface)} ${txt(m.peer_id)}`).join(' ');
      return `${txt(g.name)} ${txt(g.id)} ${txt(g.address_list)} ${members}`.toLowerCase();
    }
    function clientSearchText(c) {
      return `${txt(c.name)} ${txt(c.group_names)} ${effectiveLimitText(c)} ${txt(c.ip)} ${txt(c.interface)} ${txt(c.peer_id)}`.toLowerCase();
    }
    function clientHasPolicyOrSpeedLimit(c) {
      if (!c) return false;
      return Number(c.speed_limit_down_bps || 0) > 0
        || Number(c.speed_limit_up_bps || 0) > 0
        || Number(c.traffic_limit_down_bytes || 0) > 0
        || Number(c.traffic_limit_up_bytes || 0) > 0
        || Number(c.traffic_period_seconds || 0) > 0
        || String(c.overlimit_mode || 'disable') !== 'disable'
        || Number(c.overlimit_speed_down_bps || 0) > 0
        || Number(c.overlimit_speed_up_bps || 0) > 0
        || clientIsGroupMember(c);
    }
    function clientIsOverlimited(c) {
      if (!c) return false;
      if (c.overlimit_active) return true;
      return Number(c.limit_conflict_count || 0) > 0
        || (Number(c.traffic_limit_down_bytes || 0) > 0 && Number(c.download_since_now_bytes || 0) >= Number(c.traffic_limit_down_bytes || 0))
        || (Number(c.traffic_limit_up_bytes || 0) > 0 && Number(c.upload_since_now_bytes || 0) >= Number(c.traffic_limit_up_bytes || 0));
    }
    function clientMatchesFilter(c, filter) {
      const mode = String(filter || 'all');
      if (mode === 'disabled') return c.state === 'disabled';
      if (mode === 'enabled') return c.state !== 'disabled';
      if (mode === 'groups') return clientIsGroupMember(c);
      if (mode === 'singles') return !clientIsGroupMember(c);
      if (mode === 'overlimited') return clientIsOverlimited(c);
      if (mode === 'without_limits') return !clientHasPolicyOrSpeedLimit(c);
      return true;
    }
    function compareClientRows(a, b) {
      const av = sortKey === 'quota_pct' ? (clientQuotaPct(a) ?? -1) : (sortKey === 'speed_pct' ? (clientSpeedPct(a) ?? -1) : a[sortKey]);
      const bv = sortKey === 'quota_pct' ? (clientQuotaPct(b) ?? -1) : (sortKey === 'speed_pct' ? (clientSpeedPct(b) ?? -1) : b[sortKey]);
      if (typeof av === 'number' && typeof bv === 'number') return sortDesc ? (bv - av) : (av - bv);
      const aa = txt(av).toLowerCase();
      const bb = txt(bv).toLowerCase();
      if (sortKey === 'ip') {
        const aParts = aa.split('.').map(n => parseInt(n || '0', 10));
        const bParts = bb.split('.').map(n => parseInt(n || '0', 10));
        for (let i = 0; i < 4; i += 1) {
          const d = (aParts[i] || 0) - (bParts[i] || 0);
          if (d !== 0) return sortDesc ? -d : d;
        }
        return 0;
      }
      if (aa < bb) return sortDesc ? 1 : -1;
      if (aa > bb) return sortDesc ? -1 : 1;
      return 0;
    }
    function buildGroupSummaryRow(group, members) {
      const sum = (key) => members.reduce((acc, row) => acc + Number(row[key] || 0), 0);
      const groupDownUsed = group.download_since_now_bytes;
      const groupUpUsed = group.upload_since_now_bytes;
      const memberDownUsed = sum('download_since_now_bytes');
      const memberUpUsed = sum('upload_since_now_bytes');
      const routerDownUsed = groupDownUsed === null || groupDownUsed === undefined ? null : Number(groupDownUsed || 0);
      const routerUpUsed = groupUpUsed === null || groupUpUsed === undefined ? null : Number(groupUpUsed || 0);
      const downUsed = routerDownUsed === null || routerDownUsed > 0 ? Number(routerDownUsed || 0) : memberDownUsed;
      const upUsed = routerUpUsed === null || routerUpUsed > 0 ? Number(routerUpUsed || 0) : memberUpUsed;
      const downSpeed = sum('down_speed_bps');
      const upSpeed = sum('up_speed_bps');
      const downLimit = Number(group.traffic_limit_down_bytes || 0);
      const upLimit = Number(group.traffic_limit_up_bytes || 0);
      const downCap = Number(group.speed_limit_down_bps || 0);
      const upCap = Number(group.speed_limit_up_bps || 0);
      return {
        is_group_row: true,
        group_id: group.id,
        peer_id: `group:${group.id}`,
        name: group.name,
        group_names: group.name,
        interface: 'group',
        ip: group.address_list,
        state: `${members.length} users`,
        download_since_now_bytes: downUsed,
        upload_since_now_bytes: upUsed,
        download_since_now: hBytes(downUsed),
        upload_since_now: hBytes(upUsed),
        total_download_bytes: sum('total_download_bytes'),
        total_upload_bytes: sum('total_upload_bytes'),
        down_speed_bps: downSpeed,
        up_speed_bps: upSpeed,
        down_speed: hBps(downSpeed),
        up_speed: hBps(upSpeed),
        traffic_limit_down_bytes: downLimit,
        traffic_limit_up_bytes: upLimit,
        traffic_period_seconds: Number(group.traffic_period_seconds || 0),
        traffic_reset_elapsed_seconds: Number(group.traffic_reset_elapsed_seconds || 0),
        traffic_reset_remaining_seconds: Number(group.traffic_reset_remaining_seconds || 0),
        overlimit_mode: group.overlimit_mode || 'disable',
        overlimit_speed_down_bps: Number(group.overlimit_speed_down_bps || 0),
        overlimit_speed_up_bps: Number(group.overlimit_speed_up_bps || 0),
        overlimit_active: Boolean(group.overlimit_active),
        speed_limit_down_bps: downCap,
        speed_limit_up_bps: upCap,
        effective_speed_scope: downCap > 0 || upCap > 0 ? 'group' : 'none',
        effective_policy_scope: downLimit > 0 || upLimit > 0 ? 'group' : 'none',
        limit_conflict_count: 0,
      };
    }
    function deriveGroupsFromClients(rows) {
      const byGroup = new Map();
      for (const client of rows || []) {
        const refs = Array.isArray(client.groups) ? client.groups : [];
        for (const ref of refs) {
          const id = String(ref.id || ref.name || '').trim();
          if (!id) continue;
          if (!byGroup.has(id)) {
            byGroup.set(id, {
              id,
              name: String(ref.name || id),
              peer_ids: [],
              members: [],
              member_count: 0,
              address_list: String(ref.address_list || ''),
              speed_limit_down_bps: Number(ref.speed_limit_down_bps || 0),
              speed_limit_up_bps: Number(ref.speed_limit_up_bps || 0),
              traffic_limit_down_bytes: Number(ref.traffic_limit_down_bytes || 0),
              traffic_limit_up_bytes: Number(ref.traffic_limit_up_bytes || 0),
              traffic_period_seconds: Number(ref.traffic_period_seconds || 0),
              overlimit_mode: String(ref.overlimit_mode || 'disable'),
              overlimit_speed_down_bps: Number(ref.overlimit_speed_down_bps || 0),
              overlimit_speed_up_bps: Number(ref.overlimit_speed_up_bps || 0),
              download_since_now_bytes: 0,
              upload_since_now_bytes: 0,
              overlimit_active: false,
              traffic_reset_elapsed_seconds: 0,
              traffic_reset_remaining_seconds: 0,
              created_at: 0,
              updated_at: 0,
              derived_from_clients: true,
            });
          }
          const group = byGroup.get(id);
          if (!group.peer_ids.includes(client.peer_id)) {
            group.peer_ids.push(client.peer_id);
            group.members.push({
              peer_id: client.peer_id,
              name: client.name || '',
              ip: client.ip || '',
              interface: client.interface || '',
              missing: 'false',
            });
          }
        }
      }
      const out = Array.from(byGroup.values());
      for (const group of out) group.member_count = group.peer_ids.length;
      out.sort((a, b) => String(a.name || a.id).localeCompare(String(b.name || b.id)));
      return out;
    }
    function snapshotRowsWithGroups(rows) {
      const base = Array.isArray(rows) ? rows : [];
      if (!base.length || !groupsCache.length) return base;
      const rowById = new Map(base.map((c) => [c.peer_id, c]));
      const groupRows = [];
      for (const group of groupsCache) {
        const members = (group.peer_ids || []).map((pid) => rowById.get(pid)).filter(Boolean);
        if (!members.length) continue;
        groupRows.push(buildGroupSummaryRow(group, members));
      }
      return [...base, ...groupRows];
    }
    function miniBarHtml(pct) {
      if (pct === null || pct === undefined || !Number.isFinite(Number(pct))) return '<span class="mini-val">not set</span>';
      const p = Math.max(0, Math.min(999, Number(pct)));
      const cls = p >= 100 ? 'bad' : (p >= 80 ? 'warn' : '');
      return `<div class="mini-wrap"><div class="mini-track"><div class="mini-fill ${cls}" style="width:${Math.min(100, p)}%;"></div></div><div class="mini-val">${p.toFixed(0)}%</div></div>`;
    }
    function actionGraphCard(title, used, total, usedText, totalText) {
      if (total <= 0) {
        return `<div class="ag-card"><div class="ag-title">${title}</div><div class="snap-empty">not set</div></div>`;
      }
      const u = Math.max(0, Number(used || 0));
      const t = Math.max(1, Number(total || 0));
      const ratio = (u / t) * 100;
      const pct = Math.max(0, Math.min(100, ratio));
      const cls = ratio >= 100 ? 'bad' : (ratio >= 80 ? 'warn' : '');
      const rem = Math.max(0, t - u);
      const usedPct = Math.max(0, ratio).toFixed(0);
      const remPct = Math.max(0, 100 - ratio).toFixed(0);
      return `<div class="ag-card">
        <div class="ag-title">${title}</div>
        <div class="ag-track"><div class="ag-fill ${cls}" style="width:${pct}%;"></div></div>
        <div class="ag-meta">
          <div>Used: ${usedText(u)} / Total: ${totalText(t)} (${usedPct}%)</div>
          <div>Remaining: ${totalText(rem)} (${remPct}%)</div>
        </div>
      </div>`;
    }
    function clientPrimaryGroup(c) {
      if (!c || !clientIsGroupMember(c)) return null;
      const refs = Array.isArray(c.groups) ? c.groups : [];
      for (const ref of refs) {
        const id = String(ref.id || '');
        const found = groupsCache.find((g) => String(g.id || '') === id);
        if (found) return found;
      }
      const names = String(c.group_names || '').split(',').map((x) => x.trim()).filter(Boolean);
      for (const name of names) {
        const found = groupsCache.find((g) => String(g.name || '') === name);
        if (found) return found;
      }
      return null;
    }
    function actionGraphSource(c) {
      const group = clientPrimaryGroup(c);
      if (!group) return c;
      return {
        download_since_now_bytes: Number(c.download_since_now_bytes || 0),
        upload_since_now_bytes: Number(c.upload_since_now_bytes || 0),
        down_speed_bps: Number(c.down_speed_bps || 0),
        up_speed_bps: Number(c.up_speed_bps || 0),
        traffic_limit_down_bytes: Number(group.traffic_limit_down_bytes || 0),
        traffic_limit_up_bytes: Number(group.traffic_limit_up_bytes || 0),
        speed_limit_down_bps: Number(group.speed_limit_down_bps || 0),
        speed_limit_up_bps: Number(group.speed_limit_up_bps || 0),
        traffic_period_seconds: Number(group.traffic_period_seconds || 0),
        traffic_reset_elapsed_seconds: Number(group.traffic_reset_elapsed_seconds || 0),
        traffic_reset_remaining_seconds: Number(group.traffic_reset_remaining_seconds || 0),
      };
    }
    function renderActionsUserGraphs(rows) {
      const wrap = byId('actionsUserGraphsWrap');
      const host = byId('actionsUserGraphs');
      if (!wrap || !host) return;
      if (!rows || rows.length !== 1) {
        wrap.style.display = 'none';
        host.innerHTML = '';
        return;
      }
      const c = actionGraphSource(rows[0]);
      const downUsed = Number(c.download_since_now_bytes || 0);
      const upUsed = Number(c.upload_since_now_bytes || 0);
      const downLim = Number(c.traffic_limit_down_bytes || 0);
      const upLim = Number(c.traffic_limit_up_bytes || 0);
      const downNow = Number(c.down_speed_bps || 0);
      const upNow = Number(c.up_speed_bps || 0);
      const downCap = Number(c.speed_limit_down_bps || 0);
      const upCap = Number(c.speed_limit_up_bps || 0);
      const resetElapsed = Number(c.traffic_reset_elapsed_seconds || 0);
      const resetRemaining = Number(c.traffic_reset_remaining_seconds || 0);
      const resetTotal = Number(c.traffic_period_seconds || 0);
      host.innerHTML = [
        actionGraphCard('Download Quota', downUsed, downLim, (v) => hBytes(v), (v) => hBytes(v)),
        actionGraphCard('Upload Quota', upUsed, upLim, (v) => hBytes(v), (v) => hBytes(v)),
        actionGraphCard('Download Speed', downNow, downCap, (v) => hBps(v), (v) => hBps(v)),
        actionGraphCard('Upload Speed', upNow, upCap, (v) => hBps(v), (v) => hBps(v)),
        actionGraphCard('Traffic Reset Window', resetElapsed, resetTotal, (v) => hDuration(v), (v) => hDuration(v)),
      ].join('');
      wrap.style.display = '';
    }
    function currentGroupSummaryRow() {
      const group = currentEditedGroup();
      if (!group) return null;
      const members = (group.peer_ids || []).map((pid) => clientsCache.find((c) => c.peer_id === pid)).filter(Boolean);
      return buildGroupSummaryRow(group, members);
    }
    function renderGroupGraphs() {
      const wrap = byId('groupGraphsWrap');
      const host = byId('groupGraphs');
      if (!wrap || !host) return;
      const c = currentGroupSummaryRow();
      if (!c) {
        wrap.style.display = 'none';
        host.innerHTML = '';
        return;
      }
      host.innerHTML = [
        actionGraphCard('Download Quota', Number(c.download_since_now_bytes || 0), Number(c.traffic_limit_down_bytes || 0), (v) => hBytes(v), (v) => hBytes(v)),
        actionGraphCard('Upload Quota', Number(c.upload_since_now_bytes || 0), Number(c.traffic_limit_up_bytes || 0), (v) => hBytes(v), (v) => hBytes(v)),
        actionGraphCard('Download Speed', Number(c.down_speed_bps || 0), Number(c.speed_limit_down_bps || 0), (v) => hBps(v), (v) => hBps(v)),
        actionGraphCard('Upload Speed', Number(c.up_speed_bps || 0), Number(c.speed_limit_up_bps || 0), (v) => hBps(v), (v) => hBps(v)),
        actionGraphCard('Traffic Reset Window', Number(c.traffic_reset_elapsed_seconds || 0), Number(c.traffic_period_seconds || 0), (v) => hDuration(v), (v) => hDuration(v)),
      ].join('');
      wrap.style.display = '';
    }
