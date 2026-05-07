    async function refreshAll(showStatus = true, options = {}) {
      const forceNew = Boolean(options.forceNew);
      if (refreshInFlight && forceNew) {
        try { await refreshInFlight; } catch (_) {}
      } else if (refreshInFlight) {
        if (showStatus) setStatus('refresh already in progress');
        return refreshInFlight;
      }
      refreshInFlight = (async () => {
        const epoch = routerDataEpoch;
        try {
          if (showStatus) setStatus('refreshing...');
          const out = await api('/api/snapshot?refresh=1', { timeoutMs: 60000 });
          if (out && out.status === 'busy') {
            if (showStatus) setStatus('refresh skipped: manager busy');
            return;
          }
          if (!isCurrentRouterDataEpoch(epoch)) return;
          await applyLiveSnapshot(out, { silentStatus: !showStatus });
          if (!isCurrentRouterDataEpoch(epoch)) return;
          if (showStatus) setStatus('refreshed');
        } catch (e) {
          setStatus(e.message, true);
        } finally {
          refreshInFlight = null;
        }
      })();
      return refreshInFlight;
    }

    (async () => {
      try {
        await loadPanelSettings();
        initTheme();
        applyPanelSettingsToControls();
        loadGroupCollapseState();
        await loadProfiles();
        const groupEl = byId('groupName');
        if (groupEl) groupEl.addEventListener('input', sanitizeGroupNameInput);
        for (const id of ['groupSpeedDown', 'groupSpeedUp', 'groupLimitDown', 'groupLimitUp', 'groupOverDown', 'groupOverUp']) {
          const el = byId(id);
          if (el) el.addEventListener('input', () => sanitizeEnglishNumberInput(id));
        }
        const groupPeriod = byId('groupPeriod');
        if (groupPeriod) groupPeriod.addEventListener('input', () => {
          groupPeriod.value = String(groupPeriod.value || '').replace(/[^A-Za-z0-9.]/g, '').slice(0, 16);
        });
        setupClientTableInteractions();
        bindDraftDirtyTracking();
        const auth = await loadAuthStatus();
        if (auth.connected) {
          await refreshAll();
          await runDiagnostics();
        } else {
          setStatus(auth.needs_profile ? 'router profile setup required' : 'router credentials required', true);
          await openAuthModal(auth.current || '');
        }
        document.querySelectorAll('.modal').forEach((m) => {
          m.addEventListener('click', (ev) => {
            if (ev.target === m) m.classList.remove('show');
          });
        });
        document.addEventListener('click', (ev) => {
          const dd = byId('actionsDropdown');
          if (dd && !dd.contains(ev.target)) closeActionsMenu();
          const settings = byId('panelSettingsDropdown');
          if (settings && !settings.contains(ev.target)) closePanelSettingsMenu();
        });
        document.addEventListener('keydown', (ev) => {
          if (ev.key === 'Escape') {
            closeActionsMenu();
            document.querySelectorAll('.modal.show').forEach((m) => m.classList.remove('show'));
          }
        });
        window.addEventListener('beforeunload', () => {
          if (liveSource) liveSource.close();
        });
      } catch (e) {
        setStatus(e.message, true);
      }
    })();
