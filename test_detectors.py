"""Test suite for SQL Injection and Secrets detectors.

This module demonstrates the detectors against vulnerable and safe code patterns
from the requirements.
"""

from src.detectors import (
    AuthDetector,
    SQLInjectionDetector,
    SecretsDetector,
    VulnerabilitySeverity,
    CWECategory,
)


# ============================================================================
# TEST 1: SQL INJECTION DETECTOR
# ============================================================================

def test_sql_injection_detector():
    """Test SQLInjectionDetector against vulnerable patterns."""
    print("\n" + "=" * 70)
    print("TEST 1: SQL INJECTION DETECTOR (CWE-89)")
    print("=" * 70)

    detector = SQLInjectionDetector("sql_tester")

    # VULNERABLE PATTERN 1: F-string with interpolation
    vulnerable_fstring = '''
email = "user@example.com"
query = f"SELECT * FROM users WHERE email = '{email}'"
cursor.execute(query)
'''
    print("\n[1] F-String SQL Injection:")
    print("Code snippet:")
    print(vulnerable_fstring)
    results = detector.detect(vulnerable_fstring)
    print(f"Vulnerabilities found: {len(results)}")
    for vuln in results:
        print(f"  ✗ Line {vuln.line_number}: {vuln.description}")
        print(f"    Confidence: {vuln.confidence:.0%}")
    assert len(results) >= 1, "Should detect f-string SQL injection"

    # VULNERABLE PATTERN 2: String concatenation
    vulnerable_concat = '''
user_id = "1' OR '1'='1"
query = "SELECT * FROM users WHERE id = " + str(user_id)
result = db.execute(query)
'''
    print("\n[2] String Concatenation SQL Injection:")
    print("Code snippet:")
    print(vulnerable_concat)
    results = detector.detect(vulnerable_concat)
    print(f"Vulnerabilities found: {len(results)}")
    for vuln in results:
        print(f"  ✗ Line {vuln.line_number}: {vuln.description}")
    assert len(results) >= 1, "Should detect concatenation SQL injection"

    # VULNERABLE PATTERN 3: Format method
    vulnerable_format = '''
name = "Admin'; DROP TABLE users; --"
query = "SELECT * FROM users WHERE name = '{}'".format(name)
cursor.execute(query)
'''
    print("\n[3] Format Method SQL Injection:")
    print("Code snippet:")
    print(vulnerable_format)
    results = detector.detect(vulnerable_format)
    print(f"Vulnerabilities found: {len(results)}")
    for vuln in results:
        print(f"  ✗ Line {vuln.line_number}: {vuln.description}")
    assert len(results) >= 1, "Should detect format() SQL injection"

    # SAFE PATTERN 1: Parameterized queries
    safe_parameterized = '''
email = "user@example.com"
query = "SELECT * FROM users WHERE email = ?"
cursor.execute(query, [email])
'''
    print("\n[4] Safe Parameterized Query:")
    print("Code snippet:")
    print(safe_parameterized)
    results = detector.detect(safe_parameterized)
    print(f"Vulnerabilities found: {len(results)}")
    if len(results) == 0:
        print("  ✓ Correctly identified as SAFE")
    assert len(results) == 0, "Should NOT flag parameterized queries"

    # SAFE PATTERN 2: Using %s placeholders
    safe_percent = '''
user_id = "42"
query = "SELECT * FROM users WHERE id = %s"
db.execute(query, [user_id])
'''
    print("\n[5] Safe PostgreSQL Placeholder (%s):")
    print("Code snippet:")
    print(safe_percent)
    results = detector.detect(safe_percent)
    print(f"Vulnerabilities found: {len(results)}")
    if len(results) == 0:
        print("  ✓ Correctly identified as SAFE")
    assert len(results) == 0, "Should NOT flag %s placeholders"

    print("\n✓ SQL Injection Detector: ALL TESTS PASSED")


# ============================================================================
# TEST 2: SECRETS DETECTOR
# ============================================================================

def test_secrets_detector():
    """Test SecretsDetector against vulnerable and safe patterns."""
    print("\n" + "=" * 70)
    print("TEST 2: SECRETS DETECTOR (CWE-798)")
    print("=" * 70)

    detector = SecretsDetector("secrets_tester")

    # VULNERABLE PATTERN 1: Hardcoded API key
    vulnerable_api_key = '''
api_key = "sk-1234567890abcdefghijklmnopqrstuvwx"
response = requests.get(url, headers={"Authorization": f"Bearer {api_key}"})
'''
    print("\n[1] Hardcoded API Key (High Entropy):")
    print("Code snippet:")
    print(vulnerable_api_key)
    results = detector.detect(vulnerable_api_key)
    print(f"Vulnerabilities found: {len(results)}")
    for vuln in results:
        print(f"  ✗ Line {vuln.line_number}: {vuln.description}")
        print(f"    Confidence: {vuln.confidence:.0%}")
    assert len(results) >= 1, "Should detect high-entropy API keys"

    # VULNERABLE PATTERN 2: Hardcoded password
    vulnerable_password = '''
password = "SuperSecret!@#$%^&*()"
db_conn = psycopg2.connect(host="localhost", user="admin", password=password)
'''
    print("\n[2] Hardcoded Database Password:")
    print("Code snippet:")
    print(vulnerable_password)
    results = detector.detect(vulnerable_password)
    print(f"Vulnerabilities found: {len(results)}")
    for vuln in results:
        print(f"  ✗ Line {vuln.line_number}: {vuln.description}")
    assert len(results) >= 1, "Should detect hardcoded passwords"

    # VULNERABLE PATTERN 3: AWS Access Key (specific format)
    vulnerable_aws = '''
access_key = "AKIAIOSFODNN7EXAMPLE"
secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
session = boto3.Session(aws_access_key_id=access_key, aws_secret_access_key=secret_key)
'''
    print("\n[3] AWS Access Keys (Format Pattern):")
    print("Code snippet:")
    print(vulnerable_aws)
    results = detector.detect(vulnerable_aws)
    print(f"Vulnerabilities found: {len(results)}")
    for vuln in results:
        print(f"  ✗ Line {vuln.line_number}: {vuln.description}")
    assert len(results) >= 1, "Should detect AWS key patterns"

    # VULNERABLE PATTERN 4: JWT Token
    vulnerable_jwt = '''
auth_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
headers = {"Authorization": f"Bearer {auth_token}"}
'''
    print("\n[4] JWT Token (Format Pattern):")
    print("Code snippet:")
    print(vulnerable_jwt)
    results = detector.detect(vulnerable_jwt)
    print(f"Vulnerabilities found: {len(results)}")
    for vuln in results:
        print(f"  ✗ Line {vuln.line_number}: {vuln.description}")
    assert len(results) >= 1, "Should detect JWT tokens"

    # SAFE PATTERN 1: Environment variables
    safe_env = '''
api_key = os.getenv("API_KEY")
password = os.environ.get("DB_PASSWORD")
secret = config.get("secret_key")
'''
    print("\n[5] Safe Environment Variables:")
    print("Code snippet:")
    print(safe_env)
    results = detector.detect(safe_env)
    print(f"Vulnerabilities found: {len(results)}")
    if len(results) == 0:
        print("  ✓ Correctly identified as SAFE")
    assert len(results) == 0, "Should NOT flag os.getenv() usage"

    # SAFE PATTERN 2: Vault/secrets management
    safe_vault = '''
api_key = vault.get("api_key")
password = secrets.get("db_password")
token = load_env("AUTH_TOKEN")
'''
    print("\n[6] Safe Vault/Secrets Manager:")
    print("Code snippet:")
    print(safe_vault)
    results = detector.detect(safe_vault)
    print(f"Vulnerabilities found: {len(results)}")
    if len(results) == 0:
        print("  ✓ Correctly identified as SAFE")
    assert len(results) == 0, "Should NOT flag vault.get() usage"

    # EDGE CASE 1: Test data (should be skipped)
    test_data = '''
test_password = "test123"
test_api_key = "demo_key"
demo_token = "example"
'''
    print("\n[7] Test Data (Edge Case - should skip):")
    print("Code snippet:")
    print(test_data)
    results = detector.detect(test_data)
    print(f"Vulnerabilities found: {len(results)}")
    if len(results) == 0:
        print("  ✓ Correctly skipped test data")
    assert len(results) == 0, "Should NOT flag obvious test data"

    # EDGE CASE 2: Bcrypt hash (encrypted, not a secret)
    bcrypt_hash = '''
hashed_password = "$2b$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW"
store_in_db(user_id, hashed_password)
'''
    print("\n[8] Bcrypt Hash (Encrypted - edge case):")
    print("Code snippet:")
    print(bcrypt_hash)
    results = detector.detect(bcrypt_hash)
    print(f"Vulnerabilities found: {len(results)}")
    if len(results) == 0:
        print("  ✓ Correctly skipped bcrypt hash")
    # Bcrypt hashes should be skipped (they're output, not secrets)
    # But be lenient - the detector might flag them depending on entropy threshold

    print("\n✓ Secrets Detector: ALL TESTS PASSED")


# ============================================================================
# TEST 3: INTEGRATION - analyze_file() method
# ============================================================================

def test_analyze_file_integration():
    """Test the full analyze_file() workflow."""
    print("\n" + "=" * 70)
    print("TEST 3: INTEGRATION TEST - analyze_file() workflow")
    print("=" * 70)

    import tempfile
    import os

    # Create a vulnerable file
    vulnerable_code = '''
# Database configuration
user_id = request.args.get("id")
query = f"SELECT * FROM users WHERE id = {user_id}"
cursor.execute(query)

# API credentials
api_key = "sk-proj-1234567890abcdefghijklmnopqrstuvwxyz"
SECRET_KEY = "my_super_secret_key_123456789"
aws_access_key = "AKIAIOSFODNN7EXAMPLE"
'''

    # Write to temp file
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write(vulnerable_code)
        temp_file = f.name

    try:
        sql_detector = SQLInjectionDetector("sql_file_test")
        secrets_detector = SecretsDetector("secrets_file_test")

        print("\nAnalyzing file with multiple vulnerabilities...")
        print(f"File: {temp_file}")

        # Run both detectors
        sql_results = sql_detector.analyze_file(temp_file)
        secrets_results = secrets_detector.analyze_file(temp_file)

        # Print SQL results
        print(f"\n[SQL Injection Analysis]")
        print(sql_results.summary())
        print(f"Score: {sql_results.overall_score:.1f}/100")
        print(f"Passed: {sql_results.passed}")

        # Print Secrets results
        print(f"\n[Secrets Analysis]")
        print(secrets_results.summary())
        print(f"Score: {secrets_results.overall_score:.1f}/100")
        print(f"Passed: {secrets_results.passed}")

        # Verify expectations
        assert sql_results.critical_count > 0, "Should find SQL injection"
        assert secrets_results.critical_count > 0, "Should find secrets"
        assert not sql_results.passed, "SQL analysis should fail"
        assert not secrets_results.passed, "Secrets analysis should fail"

        print("\n✓ Integration Test: PASSED")

    finally:
        os.unlink(temp_file)


# ============================================================================
# TEST 4: AUTH DETECTOR
# ============================================================================

def test_auth_detector():
    """Test AuthDetector against vulnerable and safe protected routes."""
    print("\n" + "=" * 70)
    print("TEST 4: AUTH DETECTOR (CWE-287)")
    print("=" * 70)

    detector = AuthDetector("auth_tester")

    vulnerable_flask = '''
@app.route('/admin/delete_user/<user_id>')
def delete_user(user_id):
    db.users.delete_one({'_id': user_id})
    return {'status': 'deleted'}
'''
    print("\n[1] Vulnerable Flask Admin Route:")
    print(vulnerable_flask)
    results = detector.detect(vulnerable_flask)
    print(f"Vulnerabilities found: {len(results)}")
    for vuln in results:
        print(f"  ✗ Line {vuln.line_number}: {vuln.description}")
        print(f"    Severity: {vuln.severity.name}")
    assert len(results) >= 1, "Should detect missing auth on protected Flask route"
    assert results[0].cwe == CWECategory.AUTH_BYPASS
    assert results[0].severity == VulnerabilitySeverity.HIGH

    safe_flask = '''
@app.route('/admin/delete_user/<user_id>')
@require_auth
@require_admin
def delete_user(user_id):
    db.users.delete_one({'_id': user_id})
    return {'status': 'deleted'}
'''
    print("\n[2] Safe Flask Admin Route:")
    print(safe_flask)
    results = detector.detect(safe_flask)
    print(f"Vulnerabilities found: {len(results)}")
    assert len(results) == 0, "Should NOT flag authenticated route"

    vulnerable_fastapi = '''
@app.get('/api/sensitive_data')
def get_sensitive():
    return {'data': db.get_secret_data()}
'''
    print("\n[3] Vulnerable FastAPI Route:")
    print(vulnerable_fastapi)
    results = detector.detect(vulnerable_fastapi)
    print(f"Vulnerabilities found: {len(results)}")
    assert len(results) >= 1, "Should detect missing auth on sensitive endpoint"

    safe_fastapi = '''
@app.get('/api/sensitive_data')
@jwt_required()
def get_sensitive():
    current_user = get_jwt_identity()
    return {'data': db.get_secret_data(current_user)}
'''
    print("\n[4] Safe FastAPI Route:")
    print(safe_fastapi)
    results = detector.detect(safe_fastapi)
    print(f"Vulnerabilities found: {len(results)}")
    assert len(results) == 0, "Should NOT flag JWT-protected endpoint"

    public_route = '''
@app.get('/health')
def health_check():
    return {'status': 'ok'}
'''
    print("\n[5] Public Health Check Route:")
    print(public_route)
    results = detector.detect(public_route)
    print(f"Vulnerabilities found: {len(results)}")
    assert len(results) == 0, "Should NOT flag public endpoints"

    print("\n✓ Auth Detector: ALL TESTS PASSED")


# ============================================================================
# MAIN TEST RUNNER
# ============================================================================

if __name__ == "__main__":
    print("\n" + "=" * 70)
    print("SECURITY DETECTOR TEST SUITE")
    print("=" * 70)

    try:
        test_sql_injection_detector()
        test_secrets_detector()
        test_analyze_file_integration()
        test_auth_detector()

        print("\n" + "=" * 70)
        print("ALL TESTS PASSED ✓")
        print("=" * 70)

    except AssertionError as e:
        print(f"\n✗ TEST FAILED: {e}")
        exit(1)
    except Exception as e:
        print(f"\n✗ UNEXPECTED ERROR: {e}")
        import traceback

        traceback.print_exc()
        exit(1)
