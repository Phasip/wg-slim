// State
let currentPeerName = null;
let peersData = [];
let serverName = null;
let last_alert_msg = null;
let last_alert_elem = null;
let last_alert_count = 0;
// Sorting defaults (initialize from localStorage)
let defaultSortKey = (localStorage.getItem('wg_sort_key')) || 'name';
let defaultSortDesc = (localStorage.getItem('wg_sort_desc') === 'true');
let defaultPlaceDisabledLast = (localStorage.getItem('wg_sort_disabled_last') === 'true');
// Utility functions
function showAlert(message, type = 'success') {
    if (last_alert_msg == message + type) {
        last_alert_elem.remove();
        message =  message + ` (${last_alert_count})`;
    } else {
        last_alert_count = 0;
        last_alert_msg = message + type;
    }
    
    last_alert_count = last_alert_count + 1;
    const container = document.getElementById('alert-container');
    const alert = document.createElement('div');
    last_alert_elem = alert;
    alert.className = `alert alert-${type} alert-dismissible fade show`;

    const text = document.createElement('span');
    text.textContent = String(message);
    alert.appendChild(text);

    const btn = document.createElement('button');
    btn.type = 'button'; 
    btn.className = 'btn-close';
    btn.setAttribute('data-bs-dismiss', 'alert'); 
    btn.setAttribute('aria-label', 'Close');
    alert.appendChild(btn);
    container.appendChild(alert);
    if (type === 'success') {
        setTimeout(() => {alert.remove();}, 5000);
    }
    
}
async function showException(e, defaultMessage = 'Operation failed') {
    try {
        // Always log the raw error for debugging
        console.error(defaultMessage + ':', e);
        // If this is an OpenAPI response wrapper, handle 401 specially
        if (e && e.response && e.response.status === 401) {
            // Unauthorized: show message and redirect to login after a short delay
            showAlert('Session expired. Redirecting to login...', 'danger');
            localStorage.removeItem('wg_access_token');
            setTimeout(() => { window.location.href = '/login'; }, 2000);
            return;
        }

        const json = await e.response.json();
        const model = OpenApiClient.ModelErrorFromJSON(json);
        showAlert(`${defaultMessage}: ${model.error}`, 'danger');
    } catch (e_ignore) {
        showAlert(`${defaultMessage}: ${e && (e.message || e)}`, 'danger');
    }
}




const _openapiConfig = new OpenApiClient.Configuration({
    basePath: '/api',
    credentials: 'same-origin',
    accessToken: function() { return localStorage.getItem('wg_access_token'); }
});
const apiClient = new OpenApiClient.DefaultApi(_openapiConfig); 

try {
    await apiClient.serverGet();
} catch (e) {
    await showException(e, 'Session validation failed');
}

document.getElementById('sort-key-button').dataset.sort = defaultSortKey;
document.querySelectorAll('#sort-key-menu [data-sort]').forEach(i => {
    if (i.dataset.sort === defaultSortKey) i.classList.add('active');
    else i.classList.remove('active');
});
document.getElementById('sort-desc').checked = defaultSortDesc;
document.getElementById('sort-disabled-last').checked = defaultPlaceDisabledLast;

// Load server info
async function loadServerInfo() {
    try {
        const data = await apiClient.serverGet();
        const serverInterfaceEl = document.getElementById('server-interface');
        if (serverInterfaceEl) {
            serverInterfaceEl.textContent = data.interface_name || '-';
        }
        // The server name is no longer stored in the DOM; keep it in a JS
        serverName = data.name || null;
    } catch (error) {
        await showException(error, 'Failed to load server info');
    }
}

// Load peers
async function loadPeers() {
    try {
        const data = await apiClient.peersGet();
        peersData = data.peers || [];
        renderPeers(peersData);
        // Update wg show blocks after peers are rendered
        await loadWgShow();
    } catch (error) {
        await showException(error, 'Failed to load peers');
    }
}

// Load raw `wg show` output split per-peer from the server and update UI
async function loadWgShow() {
    try {
        const resp = (await apiClient.wgShowGetRaw()).raw;
        const data = await resp.json();
        // data is an object mapping peer names to raw text
        for (const name of Object.keys(data)) {
            const selector = '#peers-container [data-peer="' + name + '"]';
            const el = document.querySelector(selector);
            el.textContent = data[name] || '';
        }
    } catch (err) {
        await showException(err, 'Failed to load wg show data');
    }
}

function ipToSortable(ip) {
    const MAX = 0xFFFFFFFF >>> 0;
    if (!ip) return MAX;
    const addr = String(ip).split('/')[0].trim();
    if (!addr || addr === '-') return MAX;
    // IPv4 -> convert to 32-bit integer
    const m = addr.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
    if (m) {
        const a = Number(m[1]);
        const b = Number(m[2]);
        const c = Number(m[3]);
        const d = Number(m[4]);
        if ([a,b,c,d].every(n => Number.isInteger(n) && n >= 0 && n <= 255)) {
            return (((a << 24) >>> 0) + (b << 16) + (c << 8) + d) >>> 0;
        }
    }

    return MAX;
}

// Render peers
function renderPeers(peers) {
    const container = document.getElementById('peers-container');
    if (peers.length === 0) {
        container.innerHTML = '<div class="peer-empty w-100 text-center text-muted">No peers configured</div>';
        return;
    }
    const serverNameLocal = serverName || null;

    const sortKey = document.getElementById('sort-key-button').dataset.sort || defaultSortKey;
    const sortDesc = document.getElementById('sort-desc').checked;
    const placeDisabledLast = document.getElementById('sort-disabled-last').checked;

    // Preserve existing wg-show content so sorting doesn't reset the displayed wg output
    const existingWg = {};
    document.querySelectorAll('#peers-container .wg-show').forEach(el => {
        existingWg[el.dataset.peer] = el.innerHTML;
    });

    // Sort peers according to controls
    const orderedPeers = peers.slice();
    orderedPeers.sort((a, b) => {
        // Optionally place disabled peers last
        if (placeDisabledLast && a.enabled !== b.enabled) {
            return a.enabled ? -1 : 1;
        }

        let cmp = 0;
        if (sortKey === 'name') {
            cmp = a.name.toLowerCase().localeCompare(b.name.toLowerCase());
        } else if (sortKey === 'ip') {
            const aIp = getPeerAddress(a);
            const bIp = getPeerAddress(b);
            const aNum = ipToSortable(aIp === '-' ? null : aIp);
            const bNum = ipToSortable(bIp === '-' ? null : bIp);

            if (aNum < bNum) cmp = -1;
            else if (aNum > bNum) cmp = 1;
            else cmp = 0;
        }

        return sortDesc ? -cmp : cmp;
    });

    // Keep server peer at the first position if present
    if (serverNameLocal) {
        const idx = orderedPeers.findIndex(p => p.name === serverNameLocal);
        if (idx > 0) {
            const [srv] = orderedPeers.splice(idx, 1);
            orderedPeers.unshift(srv);
        }
    }

    container.innerHTML = orderedPeers.map(peer => `
            <div class="peer-item mb-3 ${peer.name === serverNameLocal ? 'peer-server' : ''}">
            <div class="card ${!peer.enabled ? 'border-secondary opacity-75' : ''}">
                <div class="card-header d-flex justify-content-between align-items-center">
                    <span class="fw-bold">${escapeHtml(peer.name)}</span>
                    <span>${escapeHtml(getPeerAddress(peer))}</span>
                    <div>
                        ${peer.name === serverNameLocal ? '<span class="badge badge-server me-1">Server</span>' : ''}
                        ${peer.default ? '<span class="badge bg-info me-1">Default</span>' : ''}
                        <span class="badge ${peer.enabled ? 'bg-success' : 'bg-secondary'}">
                            ${peer.enabled ? 'Enabled' : 'Disabled'}
                        </span>
                    </div>
                </div>
                <div class="card-body d-flex flex-column">
                    <pre class="wg-show bg-light p-2 small" data-peer="${escapeHtml(peer.name)}">${existingWg[peer.name] || 'Loading wg show...'}</pre>
                    <div class="btn-group btn-group-sm w-100 mt-auto" role="group">
                        <a href="#" class="btn btn-outline-primary" data-action="show-qr" data-peer="${escapeHtml(peer.name)}" title="QR Code">
                            <i class="bi bi-qr-code"></i>
                        </a>
                        <a href="#" class="btn btn-outline-info" data-action="show-config" data-peer="${escapeHtml(peer.name)}" title="Config">
                            <i class="bi bi-file-text"></i>
                        </a>
                        <a href="#" class="btn btn-outline-secondary" data-action="edit-peer" data-peer="${escapeHtml(peer.name)}" title="Edit Config">
                            <i class="bi bi-pencil"></i>
                        </a>
                        <!-- Regenerate key button moved to Edit Peer modal as a checkbox -->
                        ${peer.name === serverNameLocal ? '' : `
                        <a href="#" class="btn btn-outline-${peer.enabled ? 'secondary' : 'success'}" data-action="toggle-enabled" data-peer="${escapeHtml(peer.name)}" title="${peer.enabled ? 'Disable' : 'Enable'}">
                            <i class="bi bi-${peer.enabled ? 'pause' : 'play'}"></i>
                        </a>
                        `}
                    </div>
                </div>
            </div>
        </div>
    `).join('');
}

// Helper functions
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Return a display string for a peer's Address using only the
// OpenAPI-defined `interface` field. Do not inspect `as_peer` or
// attempt to parse AllowedIPs.
function getPeerAddress(peer) {
    const m = peer._interface.match(/Address\s*=\s*(.+)/i);
    if (m && m[1]) {
        return m[1].trim();
    }

    return '-';
}


// Action handlers
async function showQR(peerName) {
    document.getElementById('qr-peer-name').textContent = peerName;
    const imgEl = document.getElementById('qr-image');
    try {
        const resp = (await apiClient.peersPeerNameQrGetRaw({ peerName })).raw;
        const blob = await resp.blob();
        const url = URL.createObjectURL(blob);
        imgEl.src = url;
        imgEl.dataset.blobUrl = url;
    } catch (err) {
        await showException(err, 'Failed to load QR code');
        return;
    }

    new bootstrap.Modal(document.getElementById('qrModal')).show();
}

async function showConfig(peerName) {
    try {
        const data = await apiClient.peersPeerNameConfigGet({ peerName });
        currentPeerName = peerName;
        document.getElementById('config-peer-name').textContent = peerName;
        document.getElementById('config-content').textContent = data.config;
        new bootstrap.Modal(document.getElementById('configModal')).show();
    } catch (error) {
        await showException(error, 'Failed to load config');
    }
}

document.getElementById('qrModal').addEventListener('hidden.bs.modal', function() {
    const imgEl = document.getElementById('qr-image');
    const u = imgEl.dataset.blobUrl;
    try { URL.revokeObjectURL(imgEl.dataset.blobUrl); } catch (e) {}
});



async function togglePeerEnabled(peerName) {
    const peer = peersData.find(p => p.name === peerName);
    if (!peer) return;
    
    try {
        if (peer.enabled) {
            await apiClient.peersPeerNameDisablePost({ peerName });
            showAlert(`Peer ${peerName} disabled`);
        } else {
            await apiClient.peersPeerNameEnablePost({ peerName });
            showAlert(`Peer ${peerName} enabled`);
        }
        loadPeers();
    } catch (error) {
        await showException(error, 'Failed to toggle peer');
    }
}



async function editPeer(peerName) {
    try {
        const data = await apiClient.peersPeerNameYamlGet({ peerName });
        currentPeerName = peerName;
        document.getElementById('edit-peer-name').textContent = peerName;
        document.getElementById('peer-yaml-config').value = data.yaml;
        document.getElementById('peer-update-all').checked = false;
        new bootstrap.Modal(document.getElementById('editPeerModal')).show();
    } catch (error) {
        await showException(error, 'Failed to load peer config');
    }
}

async function editServer() {
    try {
        const data = await apiClient.serverYamlGet();
        document.getElementById('server-yaml-config').value = data.yaml;
        new bootstrap.Modal(document.getElementById('editServerModal')).show();
    } catch (error) {
        await showException(error, 'Failed to load server config');
    }
}

async function deletePeer() {
    if (!currentPeerName) return;
    try {
        await apiClient.peersPeerNameDelete({ peerName: currentPeerName });
        showAlert(`Peer ${currentPeerName} deleted`);
        // Also hide the edit modal if it's open
        const editInstance = bootstrap.Modal.getInstance(document.getElementById('editPeerModal'));
        if (editInstance) { editInstance.hide(); }
        bootstrap.Modal.getInstance(document.getElementById('deleteModal')).hide();
        loadPeers();
    } catch (error) {
        await showException(error, 'Failed to delete peer');
    }
}

// Event delegation for peer actions
document.getElementById('peers-container').addEventListener('click', function(e) {
    const target = e.target.closest('[data-action]');
    if (!target) return;
    
    e.preventDefault();
    const action = target.dataset.action;
    const peerName = target.dataset.peer;

    switch (action) {
        case 'show-qr':
            showQR(peerName);
            break;
        case 'show-config':
            showConfig(peerName);
            break;
        case 'edit-peer':
            editPeer(peerName);
            break;

        case 'toggle-enabled':
            togglePeerEnabled(peerName);
            break;
    }
});

// Button event listeners
document.getElementById('btn-refresh')?.addEventListener('click', function() {
    loadServerInfo();
    loadPeers();
});

async function addPeer() {
    const name = document.getElementById('peer-name').value.trim();
    if (!name) {
        showAlert('Please enter a peer name', 'warning');
        return;
    }
    try {
        await apiClient.peersPost({ peersPostRequest: { name } });
        showAlert(`Peer ${name} created`);
        bootstrap.Modal.getInstance(document.getElementById('addPeerModal')).hide();
        document.getElementById('peer-name').value = '';
        loadPeers();
    } catch (error) {
        await showException(error, 'Failed to add peer');
    }
}

document.getElementById('btn-add-peer').addEventListener('click', addPeer);

// Handle enter key in peer name input
document.getElementById('peer-name').addEventListener('keydown', function(event) {
    if (event.key === 'Enter') {
        event.preventDefault();
        addPeer();
    }
});

// Handle form submission
document.getElementById('add-peer-form').addEventListener('submit', function(event) {
    event.preventDefault();
    addPeer();
});

// Handle enter key in password fields for change password modal
['current-password', 'new-password', 'confirm-password'].forEach(function(fieldId) {
    document.getElementById(fieldId).addEventListener('keydown', function(event) {
        if (event.key === 'Enter') {
            event.preventDefault();
            document.getElementById('btn-change-password').click();
        }
    });
});

// Handle form submission for change password modal
document.getElementById('change-password-form').addEventListener('submit', function(event) {
    event.preventDefault();
    document.getElementById('btn-change-password').click();
});

// Handle Ctrl+Enter in textarea fields for YAML/config modals
const textareaConfigs = [
    { fieldId: 'yaml-config', buttonId: 'btn-save-config' },
    { fieldId: 'peer-yaml-config', buttonId: 'btn-save-peer-config' },
    { fieldId: 'server-yaml-config', buttonId: 'btn-save-server-config' },
    { fieldId: 'wg-config-input', buttonId: 'btn-import-wg' }
];

textareaConfigs.forEach(function(config) {
    document.getElementById(config.fieldId).addEventListener('keydown', function(event) {
        if (event.key === 'Enter' && event.ctrlKey) {
            event.preventDefault();
            document.getElementById(config.buttonId).click();
        }
    });
});

document.getElementById('btn-download-config').addEventListener('click', function() {
    if (!currentPeerName) return;
    const config = document.getElementById('config-content').textContent;
    const blob = new Blob([config], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${currentPeerName}.conf`;
    a.click();
    URL.revokeObjectURL(url);
});

document.getElementById('btn-confirm-delete').addEventListener('click', deletePeer);

document.getElementById('btn-delete-from-edit')?.addEventListener('click', function() {
    if (!currentPeerName) return;
    document.getElementById('delete-peer-name').textContent = currentPeerName;
    new bootstrap.Modal(document.getElementById('deleteModal')).show();
});

document.getElementById('btn-edit-server')?.addEventListener('click', editServer);

document.getElementById('btn-save-server-config').addEventListener('click', async function() {
    try {
        await apiClient.serverYamlPut({ serverYamlPutRequest: { yaml: document.getElementById('server-yaml-config').value } });
        showAlert('Server configuration saved');
        bootstrap.Modal.getInstance(document.getElementById('editServerModal')).hide();
        loadServerInfo();
    } catch (error) {
        await showException(error, 'Failed to save server configuration');
    }
});

document.getElementById('btn-save-peer-config').addEventListener('click', async function() {
    if (!currentPeerName) return;

    const updateAll = document.getElementById('peer-update-all').checked;
    const regenKeys = document.getElementById('peer-regenerate-keys')?.checked;

    try {
        await apiClient.peersPeerNameYamlPut({ peerName: currentPeerName, peersPeerNameYamlPutRequest: { yaml: document.getElementById('peer-yaml-config').value } });

        if (updateAll) {
            await apiClient.updateAllPeersPost({ updateAllPeersPostRequest: { template_peer: currentPeerName } });
            showAlert(`Peer '${currentPeerName}' saved and applied to all peers`);
        } else {
            showAlert(`Peer '${currentPeerName}' saved`);
        }

        // If regenerate keys checkbox is selected, call regenerate endpoint
        if (regenKeys) {
            try {
                await apiClient.peersPeerNameRegenerateKeyPost({ peerName: currentPeerName });
                showAlert(`Keys regenerated for ${currentPeerName}`);
            } catch (err) {
                await showException(err, 'Failed to regenerate keys after save');
            }
        }

        bootstrap.Modal.getInstance(document.getElementById('editPeerModal')).hide();
        loadPeers();
    } catch (error) {
        await showException(error, 'Failed to save peer configuration');
    }
});

document.getElementById('btn-change-password').addEventListener('click', async function() {
    const current = document.getElementById('current-password').value;
    const newPass = document.getElementById('new-password').value;
    const confirm = document.getElementById('confirm-password').value;
    
    if (newPass !== confirm) {
        showAlert('Passwords do not match', 'warning');
        return;
    }
    
    try {
        await apiClient.settingsPasswordPut({ settingsPasswordPutRequest: { current_password: current, new_password: newPass, confirm_password: confirm } });
        showAlert('Password changed successfully');
        bootstrap.Modal.getInstance(document.getElementById('changePasswordModal')).hide();
        document.getElementById('change-password-form').reset();
    } catch (e) {
        await showException(e, 'Failed to change password');
    }
});

// Load YAML config when modal opens
document.getElementById('editConfigModal').addEventListener('show.bs.modal', async function() {
    try {
        const data = await apiClient.configGet();
        document.getElementById('yaml-config').value = data.config;
    } catch (error) {
        await showException(error, 'Failed to load configuration');
    }
});

document.getElementById('btn-save-config').addEventListener('click', async function() {
    try {
        await apiClient.configPut({ configPutRequest: { yaml: document.getElementById('yaml-config').value } });
        showAlert('Configuration saved successfully');
        bootstrap.Modal.getInstance(document.getElementById('editConfigModal')).hide();
        loadServerInfo();
        loadPeers();
    } catch (error) {
        await showException(error, 'Failed to save configuration');
    }
});

// Logs functionality
let logsAutoRefreshInterval = null;



async function loadLogs() {
    const container = document.getElementById('logs-container');
    const statsEl = document.getElementById('logs-stats');

    try {
        const data = await apiClient.serverLogsGet();
        const logs = data.logs;
        statsEl.textContent = '';

        const logsHtml = logs.map(logLine => {
            return `<div class="log-entry text-light">${escapeHtml(logLine)}</div>`;
        }).join('');

        container.innerHTML = logsHtml;

        container.scrollTop = 0;
    } catch (error) {
        container.innerHTML = '<div class="text-danger">Failed to load logs</div>';
        await showException(error, 'Failed to load logs');
    }
}

async function clearLogs() {
    try {
        await apiClient.serverLogsDelete();
        showAlert('Logs cleared');
        loadLogs();
    } catch (error) {
        await showException(error, 'Failed to clear logs');
    }
}

// Log level filtering removed from UI and API.

// Logs modal event listeners
document.getElementById('logsModal').addEventListener('show.bs.modal', function() {
    loadLogs();
});

document.getElementById('logsModal').addEventListener('hidden.bs.modal', function() {
    // Stop auto-refresh when modal is closed
    if (logsAutoRefreshInterval) {
        clearInterval(logsAutoRefreshInterval);
        logsAutoRefreshInterval = null;
    }
    document.getElementById('logs-auto-refresh').checked = false;
});
document.getElementById('btn-refresh-logs').addEventListener('click', loadLogs);
document.getElementById('btn-clear-logs').addEventListener('click', clearLogs);

document.getElementById('logs-auto-refresh').addEventListener('change', function() {
    if (this.checked) {
        logsAutoRefreshInterval = setInterval(loadLogs, 5000);
    } else {
        if (logsAutoRefreshInterval) {
            clearInterval(logsAutoRefreshInterval);
            logsAutoRefreshInterval = null;
        }
    }
});

// Import from WG config
document.getElementById('btn-import-wg').addEventListener('click', async function() {
    const wgConfig = document.getElementById('wg-config-input').value;
    const endpoint = document.getElementById('wg-import-endpoint').value;
    
    if (!wgConfig.trim()) {
        showAlert('Please paste a WireGuard configuration', 'danger');
        return;
    }
    if (!endpoint.trim()) {
        showAlert('Please enter the server endpoint', 'danger');
        return;
    }
    // Extra confirmation: warn users that importing will overwrite peers and server info
    const confirmMessage = 'Warning: importing a WireGuard configuration will overwrite ALL peers and server settings. This will remove existing peer information and may include losing the server peer\'s private key. Are you sure you want to continue?';
    if (!confirm(confirmMessage)) {
        return;
    }
    
    try {
        await apiClient.configImportWgPost({ configImportWgPostRequest: { wg_config: wgConfig, endpoint: endpoint } });
        showAlert('Configuration imported successfully. Review the YAML config to verify.', 'success');
        bootstrap.Modal.getInstance(document.getElementById('importWgModal')).hide();
        document.getElementById('wg-config-input').value = '';
        document.getElementById('wg-import-endpoint').value = '';
        loadServerInfo();
        loadPeers();
    } catch (error) {
        await showException(error, 'Failed to import configuration');
    }
});

// Initial load — ensure server info is loaded before peers so server is highlighted
await loadServerInfo();
await loadPeers();

// Auto-refresh peers every 30 seconds
setInterval(() => {
    loadPeers();
}, 30000);

// Re-render peers when sort controls change and persist settings
document.getElementById('sort-desc')?.addEventListener('change', function() {
    try { localStorage.setItem('wg_sort_desc', this.checked ? 'true' : 'false'); } catch (e) {}
    renderPeers(peersData);
});
document.getElementById('sort-disabled-last')?.addEventListener('change', function() {
    try { localStorage.setItem('wg_sort_disabled_last', this.checked ? 'true' : 'false'); } catch (e) {}
    renderPeers(peersData);
});

// Sort key dropdown handling
document.querySelectorAll('#sort-key-menu [data-sort]').forEach(item => {
    item.addEventListener('click', function(e) {
        e.preventDefault();
        const key = this.dataset.sort;
        const btn = document.getElementById('sort-key-button');
        if (btn) {
            btn.dataset.sort = key;
        }
        // persist selection
        try { localStorage.setItem('wg_sort_key', key); } catch (e) {}
        // mark active in menu
        document.querySelectorAll('#sort-key-menu [data-sort]').forEach(i => i.classList.remove('active'));
        this.classList.add('active');
        renderPeers(peersData);
    });
});

// Logout button: use generated OpenAPI client non-raw method and redirect to login on success
document.getElementById('btn-logout').addEventListener('click', async function () {
    try {
        // non-raw method returns the parsed Success object when status is 200
        await apiClient.logoutGet();
        try { localStorage.removeItem('wg_access_token'); } catch (e) { }
        window.location.href = '/login';
        return;
    } catch (e) {
        await showException(e, 'Logout failed');
    }
});
