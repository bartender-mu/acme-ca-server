const STORAGE_KEY = 'ca-admin-api-key';

function getApiKey() {
    return sessionStorage.getItem(STORAGE_KEY) || '';
}

function setApiKey(key) {
    sessionStorage.setItem(STORAGE_KEY, key);
}

function updateStatus(message, isError) {
    const status = document.getElementById('admin-key-status');
    if (!status) {
        return;
    }
    status.textContent = message;
    status.style.color = isError ? '#dc2626' : '#22c55e';
}

function apiHeaders() {
    return {
        'X-Admin-API-Key': getApiKey(),
        'Accept': 'application/json',
    };
}

async function downloadCertificate(event) {
    const serial = event.target.dataset.serial;
    if (!serial) {
        return;
    }
    const key = getApiKey();
    if (!key) {
        updateStatus('please save the admin API key first', true);
        return;
    }

    try {
        const response = await fetch(`/admin/certificates/${serial}`, { headers: apiHeaders() });
        if (!response.ok) {
            const body = await response.text();
            throw new Error(`${response.status}: ${body}`);
        }

        const blob = await response.blob();
        const disposition = response.headers.get('Content-Disposition') || '';
        const match = /filename="([^"]+)"/.exec(disposition);
        const filename = match ? match[1] : `${serial}.zip`;

        const url = window.URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = filename;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        window.URL.revokeObjectURL(url);
        updateStatus('download started', false);
    } catch (error) {
        updateStatus(`download failed: ${error.message}`, true);
    }
}

async function revokeCertificate(event) {
    const serial = event.target.dataset.serial;
    if (!serial) {
        return;
    }
    const key = getApiKey();
    if (!key) {
        updateStatus('please save the admin API key first', true);
        return;
    }
    if (!window.confirm(`Revoke certificate ${serial}?`)) {
        return;
    }

    try {
        const response = await fetch('/admin/revoke', {
            method: 'POST',
            headers: { ...apiHeaders(), 'Content-Type': 'application/json' },
            body: JSON.stringify({ serial_number: serial }),
        });
        if (!response.ok) {
            const body = await response.text();
            throw new Error(`${response.status}: ${body}`);
        }
        window.location.reload();
    } catch (error) {
        updateStatus(`revoke failed: ${error.message}`, true);
    }
}

function initAdminControls() {
    const keyInput = document.getElementById('admin-api-key');
    const saveButton = document.getElementById('admin-save-key');
    if (keyInput && saveButton) {
        keyInput.value = getApiKey();
        saveButton.addEventListener('click', () => {
            const key = keyInput.value.trim();
            setApiKey(key);
            updateStatus(key ? 'key saved' : 'key cleared', !key);
        });
    }

    document.querySelectorAll('.admin-download').forEach((button) => {
        button.addEventListener('click', downloadCertificate);
    });
    document.querySelectorAll('.admin-revoke').forEach((button) => {
        button.addEventListener('click', revokeCertificate);
    });
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initAdminControls);
} else {
    initAdminControls();
}
