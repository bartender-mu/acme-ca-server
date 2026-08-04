const KEY_SIZE_OPTIONS = {
    'rsa': ['2048', '4096'],
    'ec': ['256', '384'],
};

let lastSerial = null;

function issueStatus(message, isError) {
    const status = document.getElementById('issue-status');
    if (!status) {
        return;
    }
    status.textContent = message;
    status.style.color = isError ? '#dc2626' : '#22c55e';
}

function addDomainRow() {
    const list = document.getElementById('domain-list');
    const row = document.createElement('div');
    row.className = 'domain-row';

    const input = document.createElement('input');
    input.type = 'text';
    input.name = 'domains';
    input.placeholder = 'example.org';
    input.required = true;

    const remove = document.createElement('button');
    remove.type = 'button';
    remove.className = 'remove-domain';
    remove.textContent = 'remove';
    remove.addEventListener('click', () => {
        row.remove();
    });

    row.appendChild(input);
    row.appendChild(remove);
    list.appendChild(row);
    input.focus();
}

function updateKeySizeOptions() {
    const keyType = document.querySelector('input[name="key-type"]:checked').value;
    const select = document.getElementById('key-size');
    const previous = select.value;
    select.innerHTML = '';
    for (const size of KEY_SIZE_OPTIONS[keyType]) {
        const option = document.createElement('option');
        option.value = size;
        option.textContent = size;
        select.appendChild(option);
    }
    if (KEY_SIZE_OPTIONS[keyType].includes(previous)) {
        select.value = previous;
    }
}

function getDomains() {
    const domains = [];
    document.querySelectorAll('#domain-list input[name="domains"]').forEach((input) => {
        const value = input.value.trim();
        if (value) {
            domains.push(value);
        }
    });
    return domains;
}

function showResult(data) {
    lastSerial = data.serial_number;
    document.getElementById('result-serial').textContent = data.serial_number;
    document.getElementById('result-not-before').textContent = new Date(data.not_before).toLocaleString();
    document.getElementById('result-not-after').textContent = new Date(data.not_after).toLocaleString();
    document.getElementById('result-private-key').textContent = data.private_key;
    document.getElementById('result-certificate').textContent = data.certificate;
    document.getElementById('result-chain').textContent = data.chain;
    document.getElementById('result').style.display = 'block';
}

async function issueCertificate(event) {
    event.preventDefault();
    const domains = getDomains();
    if (domains.length === 0) {
        issueStatus('please enter at least one domain', true);
        return;
    }
    const key = getApiKey();
    if (!key) {
        issueStatus('please save the admin API key first', true);
        return;
    }
    const keyType = document.querySelector('input[name="key-type"]:checked').value;
    const keySize = document.getElementById('key-size').value;

    issueStatus('issuing certificate...', false);
    try {
        const response = await fetch('/admin/issue', {
            method: 'POST',
            headers: { ...apiHeaders(), 'Content-Type': 'application/json' },
            body: JSON.stringify({ domains, key_type: keyType, key_size: Number(keySize) }),
        });
        if (!response.ok) {
            const body = await response.text();
            throw new Error(`${response.status}: ${body}`);
        }
        const data = await response.json();
        showResult(data);
        issueStatus('certificate issued', false);
    } catch (error) {
        issueStatus(`issue failed: ${error.message}`, true);
    }
}

async function downloadZip(event) {
    const serial = lastSerial;
    if (!serial) {
        return;
    }
    const key = getApiKey();
    if (!key) {
        issueStatus('please save the admin API key first', true);
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
        issueStatus('download started', false);
    } catch (error) {
        issueStatus(`download failed: ${error.message}`, true);
    }
}

function initIssueControls() {
    document.getElementById('add-domain').addEventListener('click', addDomainRow);
    document.querySelectorAll('input[name="key-type"]').forEach((radio) => {
        radio.addEventListener('change', updateKeySizeOptions);
    });
    document.getElementById('issue-form').addEventListener('submit', issueCertificate);
    document.getElementById('result-download').addEventListener('click', downloadZip);
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initIssueControls);
} else {
    initIssueControls();
}
