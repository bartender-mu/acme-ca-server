def test_login_page(testclient):
    response = testclient.get('/auth/login')
    assert response.status_code == 200
    assert b'<input' in response.content and b'Login' in response.content


def test_login_success(testclient):
    response = testclient.post(
        '/auth/login',
        data={'username': 'admin', 'password': 'testadmin'},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers['location'] == '/'
    assert 'session' in response.cookies


def test_login_invalid_password(testclient):
    response = testclient.post(
        '/auth/login',
        data={'username': 'admin', 'password': 'wrongpassword'},
    )
    assert response.status_code == 200
    assert b'Invalid username or password' in response.content


def test_login_invalid_username(testclient):
    response = testclient.post(
        '/auth/login',
        data={'username': 'nonexistent', 'password': 'testadmin'},
    )
    assert response.status_code == 200
    assert b'Invalid username or password' in response.content


def test_logout(testclient):
    testclient.post(
        '/auth/login',
        data={'username': 'admin', 'password': 'testadmin'},
        follow_redirects=False,
    )
    response = testclient.get('/auth/logout', follow_redirects=False)
    assert response.status_code == 303
    assert response.headers['location'] == '/auth/login'


def test_unauthenticated_redirect_to_login(testclient):
    response = testclient.get('/certificates', follow_redirects=False)
    assert response.status_code == 303
    assert response.headers['location'] == '/auth/login'


def test_authenticated_can_view_certificates(web_auth):
    response = web_auth.get('/certificates')
    assert response.status_code == 200


def test_authenticated_can_view_domains(web_auth):
    response = web_auth.get('/domains')
    assert response.status_code == 200


def test_issue_page_accessible_for_admin(web_auth):
    response = web_auth.get('/issue')
    assert response.status_code == 200
    assert b'Issue Certificate' in response.content


def test_authenticated_nav_shows_user(web_auth):
    response = web_auth.get('/')
    assert b'admin' in response.content
    assert b'Logout' in response.content


def test_authenticated_nav_shows_admin_badge(web_auth):
    response = web_auth.get('/')
    assert b'admin' in response.content


def test_unauthenticated_shows_login_link(testclient):
    response = testclient.get('/')
    assert b'Login' in response.content
