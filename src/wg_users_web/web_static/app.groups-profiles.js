    function renderGroups() {
      const list = byId('groupsList');
      if (!list) return;
      byId('groupsCount').textContent = `${groupsCache.length} groups`;
      if (!groupsCache.length) {
        list.innerHTML = '<div class="meta">No groups yet.</div>';
        return;
      }
      list.innerHTML = '';
      for (const g of groupsCache) {
        const names = (g.members || []).map((m) => txt(m.name || m.ip || m.peer_id)).join(', ');
        const limits = [
          `speed down ${g.speed_limit_down_bps > 0 ? hBps(g.speed_limit_down_bps) : 'not set'}`,
          `speed up ${g.speed_limit_up_bps > 0 ? hBps(g.speed_limit_up_bps) : 'not set'}`,
          `quota down ${g.traffic_limit_down_bytes > 0 ? hBytes(g.traffic_limit_down_bytes) : 'not set'}`,
          `quota up ${g.traffic_limit_up_bytes > 0 ? hBytes(g.traffic_limit_up_bytes) : 'not set'}`,
          `period ${hPeriod(g.traffic_period_seconds)}`,
          `mode ${txt(g.overlimit_mode)}`,
        ].join(' | ');
        const item = document.createElement('div');
        item.className = 'group-item';
        item.innerHTML = `
          <div class="group-main" title="${txt(g.address_list)}">
            <button class="link-button group-title" onclick="openGroupEditor('${g.id}')">${txt(g.name)}</button>
            <div class="group-limits">${limits}</div>
            <div class="group-members">${names || 'No members'}</div>
          </div>
          <span class="pill">${g.member_count || 0} clients</span>
          <button class="ghost" onclick="openGroupEditor('${g.id}')">Edit</button>
        `;
        list.appendChild(item);
      }
    }

    function currentEditedGroup() {
      return groupById(groupEditorId);
    }

    function openGroupEditor(groupId) {
      groupEditorId = groupId;
      groupEditorShowAll = false;
      groupDraftDirty = false;
      const showAll = byId('groupShowAllUsers');
      if (showAll) showAll.checked = false;
      fillGroupEditorForm();
      renderGroupEditor();
      openModal('groupEditorModal');
    }

    function groupAddBlockedReason(c, group) {
      const currentGroupId = group ? group.id : '';
      const groups = Array.isArray(c.groups) ? c.groups : [];
      const other = groups.find((g) => String(g.id || '') !== String(currentGroupId || ''));
      if (other) return `already in ${txt(other.name || other.id)}`;
      if (c.has_individual_limits) return 'has individual limits';
      return '';
    }

    function renderGroupEditor() {
      const group = currentEditedGroup();
      const membersBody = byId('groupMembersBody');
      const availableBody = byId('groupAvailableBody');
      if (!membersBody || !availableBody) return;
      const showAll = byId('groupShowAllUsers');
      if (showAll) showAll.checked = groupEditorShowAll;
      if (!group) {
        byId('groupEditorTitle').textContent = 'Group';
        byId('groupEditorCount').textContent = '0 members';
        const speedBtn = byId('groupSetSpeedBtn');
        const policyBtn = byId('groupSetPolicyBtn');
        if (speedBtn) speedBtn.disabled = true;
        if (policyBtn) policyBtn.disabled = true;
        membersBody.innerHTML = '<tr><td colspan="6" class="meta">No group selected.</td></tr>';
        availableBody.innerHTML = '<tr><td colspan="5" class="meta">No group selected.</td></tr>';
        renderGroupGraphs();
        return;
      }
      byId('groupEditorTitle').textContent = group.name || group.id;
      byId('groupEditorCount').textContent = `${group.member_count || 0} members`;
      const hasMembers = Number(group.member_count || 0) > 0;
      const speedBtn = byId('groupSetSpeedBtn');
      const policyBtn = byId('groupSetPolicyBtn');
      if (speedBtn) {
        speedBtn.disabled = !hasMembers;
        speedBtn.title = hasMembers ? '' : 'Add at least one member before applying group limits';
      }
      if (policyBtn) {
        policyBtn.disabled = !hasMembers;
        policyBtn.title = hasMembers ? '' : 'Add at least one member before applying group policy';
      }
      const memberIds = new Set(group.peer_ids || []);
      const members = (group.peer_ids || []).map((pid) => clientById(pid)).filter(Boolean);
      membersBody.innerHTML = members.length ? '' : '<tr><td colspan="6" class="meta">No members.</td></tr>';
      for (const c of members) {
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td>${txt(c.name)}</td>
          <td>${txt(c.ip)}</td>
          <td>${txt(c.interface)}</td>
          <td>${miniBarHtml(memberGroupQuotaPct(c, group))}</td>
          <td>${miniBarHtml(memberGroupSpeedPct(c, group))}</td>
          <td><button class="danger" onclick="removeOneFromEditedGroup('${c.peer_id}')">Remove</button></td>
        `;
        membersBody.appendChild(tr);
      }

      const q = String(byId('groupEditorSearch')?.value || '').trim().toLowerCase();
      const checkedAvailableIds = new Set(
        Array.from(document.querySelectorAll('#groupAvailableBody .group-add-cb:checked'))
          .map((el) => el.value)
          .filter(Boolean)
      );
      let available = clientsCache.filter((c) => !memberIds.has(c.peer_id));
      if (q) available = available.filter((c) => (`${txt(c.name)} ${txt(c.ip)} ${txt(c.interface)} ${txt(c.peer_id)}`).toLowerCase().includes(q));
      if (!groupEditorShowAll) available = available.filter((c) => !groupAddBlockedReason(c, group));
      available.sort(compareClientRows);
      availableBody.innerHTML = available.length ? '' : '<tr><td colspan="5" class="meta">No available users.</td></tr>';
      for (const c of available) {
        const blocked = groupAddBlockedReason(c, group);
        const checked = checkedAvailableIds.has(c.peer_id) ? 'checked' : '';
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td>${blocked ? '' : `<input type="checkbox" class="group-add-cb" value="${c.peer_id}" ${checked} />`}</td>
          <td>${txt(c.name)}</td>
          <td>${txt(c.ip)}</td>
          <td>${txt(c.interface)}</td>
          <td>${blocked || 'can be added'}</td>
        `;
        availableBody.appendChild(tr);
      }
      renderGroupGraphs();
    }

    function checkedGroupAddIds() {
      return Array.from(document.querySelectorAll('#groupAvailableBody .group-add-cb:checked')).map((el) => el.value).filter(Boolean);
    }

    function selectAllAvailableForGroup() {
      document.querySelectorAll('#groupAvailableBody .group-add-cb').forEach((el) => { el.checked = true; });
    }

    function clearAvailableForGroup() {
      document.querySelectorAll('#groupAvailableBody .group-add-cb').forEach((el) => { el.checked = false; });
    }

    async function addCheckedToEditedGroup() {
      try {
        const groupId = groupEditorId;
        const peerIds = checkedGroupAddIds();
        if (!groupId) { setStatus('Select a group first', true); return; }
        if (!peerIds.length) { setStatus('Check at least one available user', true); return; }
        const out = await api(`/api/groups/${encodeURIComponent(groupId)}/members/add`, {
          method: 'POST',
          body: JSON.stringify({ peer_ids: peerIds }),
        });
        await refreshAll(false);
        groupEditorId = groupId;
        fillGroupEditorForm();
        renderGroupEditor();
        setStatus(`group members added: ${(out.added || []).length}`);
      } catch (e) { setStatus(e.message, true); }
    }

    async function removeOneFromEditedGroup(peerId) {
      try {
        const groupId = groupEditorId;
        if (!groupId) { setStatus('Select a group first', true); return; }
        const out = await api(`/api/groups/${encodeURIComponent(groupId)}/members/remove`, {
          method: 'POST',
          body: JSON.stringify({ peer_ids: [peerId] }),
        });
        await refreshAll(false);
        groupEditorId = groupId;
        fillGroupEditorForm();
        renderGroupEditor();
        setStatus(`group members removed: ${(out.removed || []).length}`);
      } catch (e) { setStatus(e.message, true); }
    }

    function fillGroupEditorForm() {
      const groupId = groupEditorId;
      const g = groupById(groupId);
      const down = byId('groupSpeedDown');
      const up = byId('groupSpeedUp');
      if (!down || !up) return;
      down.value = g && Number(g.speed_limit_down_bps || 0) > 0 ? fmtFormNumber(Number(g.speed_limit_down_bps) / 1_000_000) : '';
      up.value = g && Number(g.speed_limit_up_bps || 0) > 0 ? fmtFormNumber(Number(g.speed_limit_up_bps) / 1_000_000) : '';
      byId('groupLimitDown').value = g && Number(g.traffic_limit_down_bytes || 0) > 0 ? fmtFormNumber(Number(g.traffic_limit_down_bytes) / (1024 * 1024 * 1024)) : '';
      byId('groupLimitUp').value = g && Number(g.traffic_limit_up_bytes || 0) > 0 ? fmtFormNumber(Number(g.traffic_limit_up_bytes) / (1024 * 1024 * 1024)) : '';
      byId('groupPeriod').value = g ? periodInputFromSeconds(g.traffic_period_seconds) : '';
      byId('groupMode').value = g ? (g.overlimit_mode || 'disable') : 'disable';
      byId('groupOverDown').value = g && Number(g.overlimit_speed_down_bps || 0) > 0 ? fmtFormNumber(Number(g.overlimit_speed_down_bps) / 1_000_000) : '';
      byId('groupOverUp').value = g && Number(g.overlimit_speed_up_bps || 0) > 0 ? fmtFormNumber(Number(g.overlimit_speed_up_bps) / 1_000_000) : '';
    }

    function renderGroupData(items, options = {}) {
      const canDeriveGroups = typeof deriveGroupsFromClients === 'function';
      groupsCache = (items && items.length) ? items : (canDeriveGroups ? deriveGroupsFromClients(clientsCache) : []);
      rebuildGroupIndex();
      renderGroups();
      if (options.renderDependents === false) {
        return;
      }
      renderSnapshotCharts(clientsCache);
      if (clientsCache.length) renderClients();
      if (groupEditorId) {
        if (!groupDraftDirty) fillGroupEditorForm();
        renderGroupEditor();
      }
    }

    async function loadGroups(options = {}) {
      const data = await api('/api/groups');
      if (!isCurrentRouterDataEpoch(options.epoch)) return;
      renderGroupData(data.items || []);
    }

    async function createGroup() {
      try {
        sanitizeGroupNameInput();
        const name = val('groupName');
        if (!name) { setStatus('Group name is required', true); return; }
        const out = await api('/api/groups', {
          method: 'POST',
          body: JSON.stringify({ name, peer_ids: [] }),
        });
        byId('groupName').value = '';
        await refreshAll(false);
        openGroupEditor(out.id);
        setStatus(`group created: ${out.name}`);
      } catch (e) { setStatus(e.message, true); }
    }

    async function setGroupSpeed() {
      try {
        const groupId = groupEditorId;
        if (!groupId) { setStatus('Select a group first', true); return; }
        const group = currentEditedGroup();
        if (!group || Number(group.member_count || 0) <= 0) {
          setStatus('Add at least one member before applying group limits', true);
          return;
        }
        sanitizeEnglishNumberInput('groupSpeedDown');
        sanitizeEnglishNumberInput('groupSpeedUp');
        const out = await api(`/api/groups/${encodeURIComponent(groupId)}/speed`, {
          method: 'POST',
          body: JSON.stringify({
            down_mbps: num('groupSpeedDown'),
            up_mbps: num('groupSpeedUp'),
          }),
        });
        await refreshAll(false);
        groupEditorId = groupId;
        groupDraftDirty = false;
        fillGroupEditorForm();
        setStatus(`group speed applied: down ${out.speed_limit_down}, up ${out.speed_limit_up}`);
      } catch (e) { setStatus(e.message, true); }
    }

    async function setGroupPolicy() {
      try {
        const groupId = groupEditorId;
        if (!groupId) { setStatus('Select a group first', true); return; }
        const group = currentEditedGroup();
        if (!group || Number(group.member_count || 0) <= 0) {
          setStatus('Add at least one member before applying group policy', true);
          return;
        }
        for (const id of ['groupLimitDown', 'groupLimitUp', 'groupOverDown', 'groupOverUp']) sanitizeEnglishNumberInput(id);
        const period = val('groupPeriod');
        if (period && !validPeriodText(period)) {
          setStatus('Group period format invalid (examples: 1d, 2h, 30m, 0)', true);
          return;
        }
        const out = await api(`/api/groups/${encodeURIComponent(groupId)}/policy`, {
          method: 'POST',
          body: JSON.stringify({
            down_gb: num('groupLimitDown'),
            up_gb: num('groupLimitUp'),
            period: period || '0',
            mode: val('groupMode') || 'disable',
            over_down_mbps: num('groupOverDown'),
            over_up_mbps: num('groupOverUp'),
          }),
        });
        await refreshAll(false);
        groupEditorId = groupId;
        groupDraftDirty = false;
        fillGroupEditorForm();
        setStatus(`group policy applied: mode ${out.overlimit_mode}`);
      } catch (e) { setStatus(e.message, true); }
    }

    async function resetGroupUsage() {
      try {
        const groupId = groupEditorId;
        if (!groupId) { setStatus('Select a group first', true); return; }
        await api(`/api/groups/${encodeURIComponent(groupId)}/reset-usage`, { method: 'POST' });
        await refreshAll(false);
        groupEditorId = groupId;
        groupDraftDirty = false;
        fillGroupEditorForm();
        renderGroupEditor();
        setStatus('group usage reset');
      } catch (e) { setStatus(e.message, true); }
    }

    async function clearGroupLimits() {
      try {
        const groupId = groupEditorId;
        if (!groupId) { setStatus('Select a group first', true); return; }
        if (!confirm('Clear speed and policy limits for this group? Members stay in the group.')) return;
        await api(`/api/groups/${encodeURIComponent(groupId)}/clear-limits`, { method: 'POST' });
        await refreshAll(false);
        groupEditorId = groupId;
        groupDraftDirty = false;
        fillGroupEditorForm();
        renderGroupEditor();
        setStatus('group limits cleared');
      } catch (e) { setStatus(e.message, true); }
    }

    async function deleteGroup() {
      try {
        const groupId = groupEditorId;
        if (!groupId) { setStatus('Select a group first', true); return; }
        if (!confirm('Delete this group? Users will stay on the router as normal users without group limits.')) return;
        await api(`/api/groups/${encodeURIComponent(groupId)}`, { method: 'DELETE' });
        if (groupEditorId === groupId) closeModal('groupEditorModal');
        await refreshAll(false);
        setStatus('group deleted');
      } catch (e) { setStatus(e.message, true); }
    }

    async function loadProfiles() {
      const data = await api('/api/profiles');
      const sel = byId('profileSelect');
      sel.innerHTML = '';
      const profiles = data.profiles || [];
      for (const p of profiles) {
        const o = document.createElement('option');
        o.value = p.name;
        const suffix = p.name === data.default ? ' default' : '';
        const auth = p.has_user === 'true' && p.has_password === 'true' ? '' : ' needs login';
        o.textContent = `${p.name} (${p.router_ip}) [${p.transport}]${suffix}${auth}`;
        if (p.name === data.current) o.selected = true;
        sel.appendChild(o);
      }
      if (!profiles.length) {
        const o = document.createElement('option');
        o.value = '';
        o.textContent = 'No router profile';
        sel.appendChild(o);
      }
      return data;
    }

    async function loadAuthStatus() {
      authStatusCache = await api('/api/auth/status');
      return authStatusCache;
    }

    function updateAuthRememberText() {
      const remembered = Boolean(byId('authRemember')?.checked);
      const mode = byId('authMode');
      const hint = byId('authHint');
      if (mode) mode.textContent = remembered ? 'remember' : 'session only';
      if (hint) {
        hint.textContent = remembered
          ? 'Router profile and credentials will be saved in the local .env file.'
          : 'Router profile details will be saved, but username/password stay only in this running server session.';
      }
    }

    async function openAuthModal(profileName = '') {
      const status = await loadAuthStatus();
      const selected = profileName || byId('profileSelect')?.value || status.current || 'default';
      let profile = null;
      if (selected) {
        try { profile = await api(`/api/profiles/${encodeURIComponent(selected)}`); } catch (_) {}
      }
      const hasRouterInfo = Boolean((profile && profile.router_ip) || status.router_ip);
      byId('authTitle').textContent = status.needs_profile ? 'Create router profile' : 'Router credentials required';
      byId('authProfileName').value = selected || 'default';
      byId('authRouterIp').value = (profile && profile.router_ip) || status.router_ip || '';
      byId('authUser').value = (profile && profile.user) || status.user || '';
      byId('authPassword').value = '';
      byId('authTransport').value = (profile && profile.transport) || 'rest';
      byId('authEndpointIp').value = (profile && profile.endpoint_ip) || '';
      document.querySelectorAll('#authModal .auth-meta-field').forEach((el) => {
        el.classList.toggle('hidden', hasRouterInfo && !status.needs_profile);
      });
      byId('authRemember').checked = false;
      updateAuthRememberText();
      openModal('authModal');
      setTimeout(() => {
        const target = !byId('authRouterIp').value ? byId('authRouterIp') : (!byId('authUser').value ? byId('authUser') : byId('authPassword'));
        if (target) target.focus();
      }, 50);
    }

    async function submitAuthLogin() {
      try {
        const body = {
          name: val('authProfileName') || 'default',
          router_ip: val('authRouterIp'),
          user: val('authUser'),
          password: val('authPassword'),
          transport: val('authTransport') || 'rest',
          endpoint_ip: val('authEndpointIp'),
          remember: Boolean(byId('authRemember')?.checked),
        };
        if (!body.name || !body.router_ip || !body.user || !body.password) {
          setStatus('Profile name, router IP, username, and password are required to connect', true);
          return;
        }
        const out = await api('/api/auth/login', {
          method: 'POST',
          body: JSON.stringify(body),
          timeoutMs: 180000,
        });
        closeModal('authModal');
        await loadProfiles();
        selectedPeerId = null;
        await refreshAll(true, { forceNew: true });
        await runDiagnostics();
        setStatus(`connected: ${out.current || body.name}`);
      } catch (e) { setStatus(e.message, true); }
    }

    function profileFormPayload() {
      return {
        name: val('pmName'),
        router_ip: val('pmRouterIp'),
        user: val('pmUser'),
        password: val('pmPassword'),
        endpoint_ip: val('pmEndpointIp'),
        dns_servers: val('pmDns'),
        transport: val('pmTransport') || 'rest',
        timeout_sec: val('pmTimeout'),
        use_https: val('pmUseHttps'),
        exempt_traffic_dst_list: val('pmExemptList'),
      };
    }

    function fillProfileForm(p) {
      byId('pmName').value = txt(p.name) === 'not set' ? '' : txt(p.name);
      byId('pmRouterIp').value = txt(p.router_ip) === 'not set' ? '' : txt(p.router_ip);
      byId('pmUser').value = txt(p.user) === 'not set' ? '' : txt(p.user);
      byId('pmPassword').value = txt(p.password) === 'not set' ? '' : txt(p.password);
      byId('pmEndpointIp').value = txt(p.endpoint_ip) === 'not set' ? '' : txt(p.endpoint_ip);
      byId('pmDns').value = txt(p.dns_servers) === 'not set' ? '' : txt(p.dns_servers);
      byId('pmTransport').value = txt(p.transport) === 'not set' ? 'rest' : txt(p.transport);
      byId('pmTimeout').value = txt(p.timeout_sec) === 'not set' ? '' : txt(p.timeout_sec);
      byId('pmUseHttps').value = txt(p.use_https) === 'not set' ? '' : txt(p.use_https);
      byId('pmExemptList').value = txt(p.exempt_traffic_dst_list) === 'not set' ? '' : txt(p.exempt_traffic_dst_list);
    }

    function renderProfileList(currentName = '') {
      const box = byId('profileList');
      if (!box) return;
      box.innerHTML = '';
      for (const p of profileManagerRows) {
        const row = document.createElement('div');
        row.className = `profile-item ${profileManagerEditName === p.name ? 'active' : ''}`;
        const defaultMark = p.is_default === 'true' ? ' default' : '';
        row.textContent = `${p.name} (${txt(p.router_ip)}) [${txt(p.transport)}]${defaultMark}`;
        row.onclick = () => editProfile(p.name);
        box.appendChild(row);
      }
      byId('pmCurrent').textContent = `current: ${currentName || '-'}`;
      byId('pmMode').textContent = profileManagerEditName ? `mode: edit (${profileManagerEditName})` : 'mode: create';
    }

    function newProfileForm() {
      profileManagerEditName = null;
      fillProfileForm({
        name: '', router_ip: '', user: '', password: '', endpoint_ip: '', dns_servers: '',
        transport: 'rest', timeout_sec: '', use_https: '', exempt_traffic_dst_list: '',
      });
      renderProfileList(byId('profileSelect')?.value || '');
    }

    async function editProfile(name) {
      try {
        const p = await api(`/api/profiles/${encodeURIComponent(name)}`);
        profileManagerEditName = p.name;
        fillProfileForm(p);
        renderProfileList(byId('profileSelect')?.value || '');
      } catch (e) { setStatus(e.message, true); }
    }

    async function loadProfileManager() {
      try {
        const data = await api('/api/profiles');
        profileManagerRows = data.profiles || [];
        const defaultSel = byId('pmDefaultProfile');
        if (defaultSel) {
          defaultSel.innerHTML = '';
          for (const p of profileManagerRows) {
            const o = document.createElement('option');
            o.value = p.name;
            o.textContent = p.name;
            if (p.name === data.default) o.selected = true;
            defaultSel.appendChild(o);
          }
        }
        renderProfileList(data.current || '');
        if (profileManagerEditName) {
          const found = profileManagerRows.find(x => x.name === profileManagerEditName);
          if (found) {
            await editProfile(profileManagerEditName);
            return;
          }
        }
        newProfileForm();
      } catch (e) { setStatus(e.message, true); }
    }

    async function openProfileModal() {
      openModal('profileModal');
      await loadProfileManager();
    }

    async function saveDefaultProfile() {
      try {
        const name = byId('pmDefaultProfile')?.value || '';
        if (!name) { setStatus('Select default router first', true); return; }
        await api('/api/profiles/default', {
          method: 'POST',
          body: JSON.stringify({ name }),
        });
        setStatus(`default router saved: ${name}`);
        await loadProfiles();
        await loadProfileManager();
      } catch (e) { setStatus(e.message, true); }
    }

    async function saveProfile() {
      try {
        const body = profileFormPayload();
        if (!body.name) { setStatus('Profile name is required', true); return; }
        if (!body.router_ip) { setStatus('router_ip is required', true); return; }
        if (profileManagerEditName) {
          await api(`/api/profiles/${encodeURIComponent(profileManagerEditName)}`, {
            method: 'PUT',
            body: JSON.stringify({
              new_name: body.name,
              router_ip: body.router_ip,
              user: body.user,
              password: body.password,
              endpoint_ip: body.endpoint_ip,
              dns_servers: body.dns_servers,
              transport: body.transport,
              timeout_sec: body.timeout_sec,
              use_https: body.use_https,
              exempt_traffic_dst_list: body.exempt_traffic_dst_list,
            }),
          });
          profileManagerEditName = body.name;
          setStatus(`profile updated: ${body.name}`);
        } else {
          await api('/api/profiles', { method: 'POST', body: JSON.stringify(body) });
          profileManagerEditName = body.name;
          setStatus(`profile created: ${body.name}`);
        }
        await loadProfiles();
        await loadProfileManager();
        await refreshAll(false);
      } catch (e) { setStatus(e.message, true); }
    }

    async function deleteProfile() {
      try {
        const name = profileManagerEditName || val('pmName');
        if (!name) { setStatus('Select profile to delete', true); return; }
        if (!confirm(`Delete router profile "${name}" from .env?`)) return;
        await api(`/api/profiles/${encodeURIComponent(name)}`, { method: 'DELETE' });
        setStatus(`profile deleted: ${name}`);
        profileManagerEditName = null;
        await loadProfiles();
        await loadProfileManager();
        await refreshAll(false);
      } catch (e) { setStatus(e.message, true); }
    }

    async function selectProfile() {
      try {
        const selected = byId('profileSelect').value;
        if (!selected) { setStatus('Select a router profile first', true); return; }
        setStatus(`switching to profile: ${selected}`);
        const previousRefresh = refreshInFlight;
        if (previousRefresh) {
          try { await previousRefresh; } catch (_) {}
        }
        const epoch = nextRouterDataEpoch();
        clearRouterScopedUiState();
        const out = await api('/api/profiles/select', {
          method: 'POST',
          body: JSON.stringify({ name: selected }),
          timeoutMs: 180000,
        });
        await loadProfiles();
        selectedPeerId = null;
        await refreshAll(true, { forceNew: true });
        if (!isCurrentRouterDataEpoch(epoch)) return;
        setStatus(`switched to profile: ${out.current || selected}`);
      } catch (e) {
        if (String(e.message || '').includes('Profile needs credentials')) {
          setStatus(e.message, true);
          await openAuthModal(byId('profileSelect').value);
          return;
        }
        setStatus(e.message, true);
      }
    }
