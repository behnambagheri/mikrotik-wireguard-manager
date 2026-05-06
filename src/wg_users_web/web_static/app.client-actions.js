    async function suggestIp() {
      try {
        const iface = byId('addIface').value;
        const data = await api(`/api/interfaces/${encodeURIComponent(iface)}/suggest-ip`);
        byId('addIp').value = data.ip;
        await loadAddIfacePoolInfo(iface);
      } catch (e) { setStatus(e.message, true); }
    }

    async function validateAddClientForm() {
      sanitizeCommentInput();
      sanitizeIpv4Input('addIp');
      sanitizePeriodInput();
      for (const id of ['addSpeedDown', 'addSpeedUp', 'addLimitDown', 'addLimitUp', 'addOverDown', 'addOverUp']) {
        sanitizeEnglishNumberInput(id);
      }
      const iface = val('addIface');
      const ip = val('addIp');
      const comment = val('addComment');
      if (!iface) { setStatus('Interface is required', true); return false; }
      if (!ip || ipv4ToInt(ip) === null) { setStatus('IP must be valid IPv4 (English digits)', true); return false; }
      const info = await loadAddIfacePoolInfo(iface);
      if (!info || !info.cidr) { setStatus('Cannot validate interface network right now', true); return false; }
      if (!ipInCidr(ip, info.cidr)) { setStatus(`IP must be in interface range ${info.cidr}`, true); return false; }
      if (String(info.interface_ip || '') === ip) { setStatus('IP cannot be the interface IP', true); return false; }
      if (Array.isArray(info.used_ips) && info.used_ips.includes(ip)) { setStatus('IP is already used', true); return false; }
      if (comment && !/^[A-Za-z0-9 -]{1,32}$/.test(comment)) {
        setStatus('Comment: only English letters/digits/space/-, max 32 chars', true);
        return false;
      }
      const numIds = ['addSpeedDown', 'addSpeedUp', 'addLimitDown', 'addLimitUp', 'addOverDown', 'addOverUp'];
      for (const id of numIds) {
        const v = val(id);
        if (!v) continue;
        if (!/^[0-9]+(\.[0-9]+)?$/.test(v) || v.length > 16) {
          setStatus(`${id} must be English number with optional dot (max 16 chars)`, true);
          return false;
        }
      }
      const period = val('addPeriod');
      if (period && !validPeriodText(period)) {
        setStatus('Period format invalid (examples: 1d, 2h, 30m, 0)', true);
        return false;
      }
      return true;
    }

    async function addClient() {
      try {
        if (!(await validateAddClientForm())) return;
        const body = {
          interface: val('addIface'),
          ip: val('addIp'),
          comment: val('addComment'),
          speed_down_mbps: numOrNull('addSpeedDown'),
          speed_up_mbps: numOrNull('addSpeedUp'),
          limit_down_gb: numOrNull('addLimitDown'),
          limit_up_gb: numOrNull('addLimitUp'),
          period: val('addPeriod') || null,
          overlimit_mode: val('addMode') || null,
          overlimit_down_mbps: numOrNull('addOverDown'),
          overlimit_up_mbps: numOrNull('addOverUp'),
        };
        const out = await api('/api/clients', { method: 'POST', body: JSON.stringify(body) });
        byId('configOut').value = out.config || '';
        byId('addConfigOut').value = out.config || '';
        lastConfigFilename = out.filename || 'client.conf';
        configForPeerId = out.peer_id || null;
        hasGeneratedConfig = Boolean((out.config || '').trim());
        selectedPeerId = out.peer_id || null;
        await refreshAll();
        setStatus(`client created: ${out.peer_id || '?'}`);
      } catch (e) { setStatus(e.message, true); }
    }

    function ensurePeer() {
      if (!selectedPeerId) throw new Error('Select a client first');
      return selectedPeerId;
    }

    async function actionSetEnable(enabled) {
      const ids = actionPeerIds();
      if (!ids.length) { setStatus('Select at least one client', true); return; }
      if (ids.length === 1) {
        selectedPeerId = ids[0];
        await toggleEnable(enabled);
        return;
      }
      await batchSetEnableSelected(enabled);
    }

    async function actionDelete() {
      const ids = actionPeerIds();
      if (!ids.length) { setStatus('Select at least one client', true); return; }
      if (ids.length === 1) {
        selectedPeerId = ids[0];
        await deleteClient();
        return;
      }
      await batchDeleteSelected();
    }

    async function actionSetSpeed() {
      const ids = actionPeerIds();
      if (!ids.length) { setStatus('Select at least one client', true); return; }
      if (ids.length === 1) {
        selectedPeerId = ids[0];
        await setSpeed();
        return;
      }
      const out = await api('/api/batch/clients/speed', {
        method: 'POST',
        body: JSON.stringify({
          peer_ids: ids,
          down_mbps: num('spDown'),
          up_mbps: num('spUp'),
        }),
      });
      actionDraftDirty = false;
      setStatus(`batch speed done: updated=${(out.updated || []).length}, skipped=${(out.skipped || []).length}`);
      await refreshAll(false);
    }

    async function actionSetPolicy() {
      const ids = actionPeerIds();
      if (!ids.length) { setStatus('Select at least one client', true); return; }
      if (ids.length === 1) {
        selectedPeerId = ids[0];
        await setPolicy();
        return;
      }
      const out = await api('/api/batch/clients/policy', {
        method: 'POST',
        body: JSON.stringify({
          peer_ids: ids,
          down_gb: num('plDown'),
          up_gb: num('plUp'),
          period: val('plPeriod') || '0',
          mode: val('plMode') || 'disable',
          over_down_mbps: num('plOverDown'),
          over_up_mbps: num('plOverUp'),
        }),
      });
      actionDraftDirty = false;
      setStatus(`batch policy done: updated=${(out.updated || []).length}, skipped=${(out.skipped || []).length}`);
      await refreshAll(false);
    }

    async function actionResetUsage() {
      const ids = actionPeerIds();
      if (!ids.length) { setStatus('Select at least one client', true); return; }
      if (ids.length === 1) {
        selectedPeerId = ids[0];
        await resetUsage();
        return;
      }
      try {
        const out = await api('/api/batch/clients/reset-usage', {
          method: 'POST',
          body: JSON.stringify({ peer_ids: ids }),
        });
        setStatus(`batch reset usage done: updated=${(out.updated || []).length}, skipped=${(out.skipped || []).length}`);
        await refreshAll(false);
      } catch (e) { setStatus(e.message, true); }
    }

    async function actionClearLimits() {
      const ids = actionPeerIds();
      if (!ids.length) { setStatus('Select at least one client', true); return; }
      if (ids.length === 1) {
        selectedPeerId = ids[0];
        await clearLimits();
        return;
      }
      try {
        const out = await api('/api/batch/clients/clear-limits', {
          method: 'POST',
          body: JSON.stringify({ peer_ids: ids }),
        });
        setStatus(`batch clear limits done: updated=${(out.updated || []).length}, skipped=${(out.skipped || []).length}`);
        await refreshAll(false);
      } catch (e) { setStatus(e.message, true); }
    }

    async function actionRevoke() {
      const ids = actionPeerIds();
      if (ids.length !== 1) { setStatus('Revoke is single-client only', true); return; }
      selectedPeerId = ids[0];
      await revokeClient();
    }

    async function toggleEnable(enabled) {
      try {
        const peer = ensurePeer();
        await api(`/api/clients/${encodeURIComponent(peer)}/enable`, { method: 'POST', body: JSON.stringify({ enabled }) });
        await refreshAll();
      } catch (e) { setStatus(e.message, true); }
    }

    async function resetUsage() {
      try {
        const peer = ensurePeer();
        await api(`/api/clients/${encodeURIComponent(peer)}/reset-usage`, { method: 'POST' });
        await refreshAll();
      } catch (e) { setStatus(e.message, true); }
    }

    async function clearLimits() {
      try {
        const peer = ensurePeer();
        await api(`/api/clients/${encodeURIComponent(peer)}/clear-limits`, { method: 'POST' });
        await refreshAll();
      } catch (e) { setStatus(e.message, true); }
    }

    async function revokeClient() {
      try {
        const peer = ensurePeer();
        if (!confirm('Revoke selected client key and generate new config?')) return;
        const out = await api(`/api/clients/${encodeURIComponent(peer)}/revoke`, { method: 'POST' });
        byId('configOut').value = out.config || '';
        lastConfigFilename = out.filename || 'client.conf';
        configForPeerId = peer;
        hasGeneratedConfig = Boolean((out.config || '').trim());
        await refreshAll();
        openModal('actionsModal');
        refreshActionsModal();
      } catch (e) { setStatus(e.message, true); }
    }

    async function deleteClient() {
      try {
        const peer = ensurePeer();
        if (!confirm('Delete selected client?')) return;
        await api(`/api/clients/${encodeURIComponent(peer)}`, { method: 'DELETE' });
        selectedPeerId = null;
        await refreshAll();
      } catch (e) { setStatus(e.message, true); }
    }

    async function batchDeleteSelected() {
      try {
        const ids = selectedRows();
        if (!ids.length) throw new Error('Select at least one client');
        if (!confirm(`Delete ${ids.length} selected client(s)?`)) return;
        const out = await api('/api/batch/clients/delete', { method: 'POST', body: JSON.stringify({ peer_ids: ids }) });
        setStatus(`batch delete done: deleted=${(out.deleted || []).length}, skipped=${(out.skipped || []).length}`);
        clearBatch();
        await refreshAll(false);
      } catch (e) { setStatus(e.message, true); }
    }

    async function batchSetEnableSelected(enabled) {
      try {
        const ids = selectedRows();
        if (!ids.length) throw new Error('Select at least one client');
        const out = await api('/api/batch/clients/enable', {
          method: 'POST',
          body: JSON.stringify({ peer_ids: ids, enabled }),
        });
        setStatus(`batch ${enabled ? 'enable' : 'disable'} done: updated=${(out.updated || []).length}, skipped=${(out.skipped || []).length}`);
        await refreshAll(false);
      } catch (e) { setStatus(e.message, true); }
    }

    async function setSpeed() {
      try {
        const peer = ensurePeer();
        const row = clientsCache.find((c) => c.peer_id === peer);
        if (clientIsGroupMember(row)) throw new Error('Individual limits cannot be applied to a user that belongs to a group');
        await api(`/api/clients/${encodeURIComponent(peer)}/speed`, {
          method: 'POST',
          body: JSON.stringify({ down_mbps: num('spDown'), up_mbps: num('spUp') })
        });
        actionDraftDirty = false;
        await refreshAll();
      } catch (e) { setStatus(e.message, true); }
    }

    async function setPolicy() {
      try {
        const peer = ensurePeer();
        const row = clientsCache.find((c) => c.peer_id === peer);
        if (clientIsGroupMember(row)) throw new Error('Individual limits cannot be applied to a user that belongs to a group');
        await api(`/api/clients/${encodeURIComponent(peer)}/policy`, {
          method: 'POST',
          body: JSON.stringify({
            down_gb: num('plDown'),
            up_gb: num('plUp'),
            period: val('plPeriod') || '0',
            mode: val('plMode') || 'disable',
            over_down_mbps: num('plOverDown'),
            over_up_mbps: num('plOverUp'),
          })
        });
        actionDraftDirty = false;
        await refreshAll();
      } catch (e) { setStatus(e.message, true); }
    }

    async function exportUsersJson() {
      try {
        const out = await api('/api/exports/users.json');
        setStatus(`users json exported: ${out.file}`);
      } catch (e) { setStatus(e.message, true); }
    }

    function exportUsersPdf() {
      window.open('/api/exports/users.pdf', '_blank');
      setStatus('users pdf export requested');
    }

    async function exportDashJson() {
      try {
        const out = await api('/api/exports/dashboard.json');
        setStatus(`dashboard json exported: ${out.file}`);
      } catch (e) { setStatus(e.message, true); }
    }

    async function exportDashCsv() {
      try {
        const out = await api('/api/exports/dashboard.csv');
        setStatus(`dashboard csv exported: ${out.file}`);
      } catch (e) { setStatus(e.message, true); }
    }

    async function copyConfig() {
      try {
        await navigator.clipboard.writeText(byId('configOut').value || '');
        setStatus('config copied to clipboard');
      } catch (e) { setStatus(`copy failed: ${e.message}`, true); }
    }

    function downloadConfig() {
      const content = byId('configOut').value || '';
      if (!content.trim()) { setStatus('no config to save', true); return; }
      const blob = new Blob([content + '\n'], { type: 'text/plain' });
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = lastConfigFilename || 'client.conf';
      a.click();
      URL.revokeObjectURL(a.href);
      setStatus('config file prepared');
    }
    async function copyAddConfig() {
      try {
        await navigator.clipboard.writeText(byId('addConfigOut').value || '');
        setStatus('add config copied to clipboard');
      } catch (e) { setStatus(`copy failed: ${e.message}`, true); }
    }
    function downloadAddConfig() {
      const content = byId('addConfigOut').value || '';
      if (!content.trim()) { setStatus('no add config to save', true); return; }
      const blob = new Blob([content + '\n'], { type: 'text/plain' });
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = lastConfigFilename || 'client.conf';
      a.click();
      URL.revokeObjectURL(a.href);
      setStatus('add config file prepared');
    }

    function toggleAuto() {
      if (liveSource || liveFallbackTimer) {
        if (liveSource) liveSource.close();
        liveSource = null;
        if (liveFallbackTimer) clearInterval(liveFallbackTimer);
        liveFallbackTimer = null;
        byId('autoBtn').textContent = 'Start';
        setStatus('live updates stopped');
        return;
      }
      const sec = Number(byId('autoSec').value || '0');
      if (sec <= 0) { setStatus('select interval > 0', true); return; }
      if (!window.EventSource) {
        liveFallbackTimer = setInterval(() => { refreshAll(false); }, sec * 1000);
        byId('autoBtn').textContent = 'Stop';
        setStatus(`live fallback refresh every ${sec}s`);
        return;
      }
      liveSource = new EventSource(`/api/live/events?interval=${encodeURIComponent(sec)}`);
      liveSource.addEventListener('snapshot', async (ev) => {
        try {
          await applyLiveSnapshot(JSON.parse(ev.data || '{}'));
        } catch (e) {
          setStatus(`live update failed: ${e.message}`, true);
        }
      });
      liveSource.addEventListener('live-error', (ev) => {
        try {
          const out = JSON.parse(ev.data || '{}');
          setStatus(out.detail || 'live stream error', true);
        } catch (e) {
          setStatus(`live stream error: ${e.message}`, true);
        }
      });
      liveSource.onerror = () => {
        setStatus('live stream reconnecting...', true);
      };
      byId('autoBtn').textContent = 'Stop';
      setStatus(`live updates every ${sec}s`);
    }
