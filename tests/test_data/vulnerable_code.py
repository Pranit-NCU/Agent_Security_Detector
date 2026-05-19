"""Vulnerable code samples used for detector positive testing.

Each sample represents intentionally insecure code and should be detected by
its corresponding detector.
"""

SQL_INJECTION_VULNERABLE_SAMPLES = [
    {
        "name": "sql_fstring_select",
        "code": 'query = f"SELECT * FROM users WHERE id = {user_id}"',
    },
    {
        "name": "sql_concat_select",
        "code": 'query = "SELECT * FROM users WHERE email = \"" + email + "\""',
    },
    {
        "name": "sql_format_select",
        "code": 'query = "SELECT * FROM users WHERE name = \"{}\"".format(name)',
    },
    {
        "name": "sql_fstring_update",
        "code": 'query = f"UPDATE users SET role = \"admin\" WHERE id = {user_id}"',
    },
    {
        "name": "sql_concat_delete",
        "code": 'query = "DELETE FROM sessions WHERE user_id = " + str(user_id)',
    },
    {
        "name": "sql_format_insert",
        "code": 'query = "INSERT INTO logs(message) VALUES(\"{}\")".format(message)',
    },
]

SECRETS_VULNERABLE_SAMPLES = [
    {
        "name": "secret_api_key",
        "code": 'api_key = "sk-1234567890abcdefghijklmnopqrst"',
    },
    {
        "name": "secret_secret_key",
        "code": 'SECRET_KEY = "super_secret_key_1234567890"',
    },
    {
        "name": "secret_aws_access",
        "code": 'access_key = "AKIAIOSFODNN7EXAMPLE"',
    },
    {
        "name": "secret_jwt_token",
        "code": 'token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTYifQ.dBjftJeZ4CVP"',
    },
    {
        "name": "secret_private_key",
        "code": 'private_key = "-----BEGIN PRIVATE KEY-----\\nMIIEvQIBADANBgkqh"',
    },
    {
        "name": "secret_db_password",
        "code": 'db_password = "ProdPass!123456"',
    },
    {
        "name": "secret_signing_key",
        "code": 'signing_key = "nNQ3Hvcfw2CH9QStn60sR3j4A9h1kLx0"',
    },
]

AUTH_VULNERABLE_SAMPLES = [
    {
        "name": "auth_flask_admin_delete",
        "code": """@app.route('/admin/delete_user/<user_id>')
def delete_user(user_id):
    db.users.delete_one({'_id': user_id})
    return {'status': 'deleted'}
""",
    },
    {
        "name": "auth_fastapi_sensitive",
        "code": """@app.get('/api/sensitive_data')
def get_sensitive_data():
    return {'data': db.get_secret_data()}
""",
    },
    {
        "name": "auth_router_delete",
        "code": """@router.delete('/user/{user_id}')
def delete_account(user_id: str):
    return {'ok': True}
""",
    },
    {
        "name": "auth_private_patch",
        "code": """@app.patch('/private/config')
def update_private_config(payload):
    return {'updated': True}
""",
    },
    {
        "name": "auth_api_admin_post",
        "code": """@app.post('/api/admin/rebuild')
def trigger_rebuild():
    return {'started': True}
""",
    },
    {
        "name": "auth_user_modify",
        "code": """@app.put('/user/modify')
def modify_user(payload):
    return {'ok': True}
""",
    },
    {
        "name": "auth_django_admin_path",
        "code": """urlpatterns = [
    path('admin/update-profile/', update_profile),
]
""",
    },
]
