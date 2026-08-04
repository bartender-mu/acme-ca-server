from .conftest import TestClient


def test_get_certificates_page(testclient: TestClient):
    response = testclient.get('/certificates')
    assert response.status_code == 200, response.text


def test_get_domains_page(testclient: TestClient):
    response = testclient.get('/domains')
    assert response.status_code == 200, response.text


def test_download_non_existent_cert(testclient: TestClient):
    response = testclient.get('/certificates/DEADBEEF')
    assert response.status_code == 404, response.text


def test_cert_log_page_has_admin_controls(testclient: TestClient):
    response = testclient.post(
        '/admin/issue',
        headers={'X-Admin-API-Key': 'test-admin-key'},
        json={'domains': ['web.example.org'], 'key_type': 'rsa', 'key_size': 2048},
    )
    assert response.status_code == 200
    serial_number = response.json()['serial_number']

    response = testclient.get('/certificates')
    assert response.status_code == 200, response.text
    assert 'admin-api-key' in response.text
    assert f'admin-download" data-serial="{serial_number}"' in response.text
    assert f'admin-revoke" data-serial="{serial_number}"' in response.text
