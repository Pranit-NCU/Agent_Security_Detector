"""Secure code baseline samples used for detector negative testing.

Each sample represents a safe implementation and should not be detected as a
vulnerability by its corresponding detector.
"""

SQL_INJECTION_SECURE_SAMPLES = [
    {
        "name": "sql_qmark_placeholder",
        "code": 'db.execute("SELECT * FROM users WHERE id = ?", [user_id])',
    },
    {
        "name": "sql_percent_s_placeholder",
        "code": 'cursor.execute("SELECT * FROM users WHERE email = %s", [email])',
    },
    {
        "name": "sql_named_placeholder",
        "code": 'conn.execute("SELECT * FROM users WHERE id = :user_id", {"user_id": user_id})',
    },
    {
        "name": "sql_insert_parameterized",
        "code": 'cursor.execute("INSERT INTO logs(message) VALUES(?)", [message])',
    },
    {
        "name": "sql_update_parameterized",
        "code": 'cursor.execute("UPDATE users SET role = ? WHERE id = ?", [role, user_id])',
    },
    {
        "name": "sql_delete_parameterized",
        "code": 'db.execute("DELETE FROM sessions WHERE user_id = ?", [user_id])',
    },
]

SECRETS_SECURE_SAMPLES = [
    {
        "name": "secret_env_getenv",
        "code": 'api_key = os.getenv("API_KEY")',
    },
    {
        "name": "secret_env_environ_get",
        "code": 'db_password = os.environ.get("DB_PASSWORD")',
    },
    {
        "name": "secret_config_get",
        "code": 'SECRET_KEY = config.get("SECRET_KEY")',
    },
    {
        "name": "secret_vault_get",
        "code": 'token = vault.get("auth_token")',
    },
    {
        "name": "secret_secrets_get",
        "code": 'api_key = secrets.get("api_key")',
    },
    {
        "name": "secret_getpass",
        "code": 'password = getpass.getpass("Password: ")',
    },
    {
        "name": "secret_test_fixture",
        "code": 'test_password = "test123"',
    },
]

AUTH_SECURE_SAMPLES = [
    {
        "name": "auth_flask_require_auth",
        "code": """@app.route('/admin/delete_user/<user_id>')
@require_auth
def delete_user(user_id):
    return {'status': 'deleted'}
""",
    },
    {
        "name": "auth_flask_login_required",
        "code": """@app.post('/api/admin/rebuild')
@login_required
def rebuild():
    return {'ok': True}
""",
    },
    {
        "name": "auth_fastapi_depends_verify",
        "code": """@router.get('/api/sensitive_data', dependencies=[Depends(verify_token)])
def get_data():
    return {'ok': True}
""",
    },
    {
        "name": "auth_jwt_required",
        "code": """@app.get('/private/dashboard')
@jwt_required()
def dashboard():
    return {'ok': True}
""",
    },
    {
        "name": "auth_permission_required",
        "code": """@permission_required('users.change_user')
@app.route('/admin/update_user')
def update_user():
    return {'ok': True}
""",
    },
    {
        "name": "auth_public_health",
        "code": """@app.get('/health')
def health():
    return {'status': 'ok'}
""",
    },
    {
        "name": "auth_public_login",
        "code": """@app.post('/login')
def login():
    return {'token': 'issued'}
""",
    },
]
