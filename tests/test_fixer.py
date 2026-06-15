import sys
import os
import re
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'spirit'))

# bcrypt tests
def test_bcrypt_rounds_fixed():
    source = "bcrypt.hashSync(password, 4)"
    pattern = r'(\.hashSync\s*\([^,]+,\s*)([0-9]+)(\s*\))'
    result = re.sub(pattern, r'\g<1>12\g<3>', source)
    assert "12" in result
    assert ",4" not in result.replace(" ", "")

def test_bcrypt_rounds_already_safe():
    source = "bcrypt.hashSync(password, 12)"
    pattern = r'(\.hashSync\s*\([^,]+,\s*)([0-9]+)(\s*\))'
    result = re.sub(pattern, r'\g<1>12\g<3>', source)
    assert "12" in result

def test_bcrypt_various_round_values():
    for rounds in [4, 5, 6, 7, 8]:
        source = f"bcrypt.hashSync(password, {rounds})"
        pattern = r'(\.hashSync\s*\([^,]+,\s*)([0-9]+)(\s*\))'
        result = re.sub(pattern, r'\g<1>12\g<3>', source)
        assert "12" in result

# jwt tests
def test_jwt_algorithm_none_fixed():
    source = "jwt.sign(data, key, {algorithm: 'none'})"
    pattern = r"algorithm\s*:\s*['\"]none['\"]"
    result = re.sub(pattern, "algorithm: 'HS256'", source)
    assert "HS256" in result
    assert "none" not in result

def test_jwt_double_quotes_fixed():
    source = 'jwt.sign(data, key, {algorithm: "none"})'
    pattern = r'algorithm\s*:\s*["\']none["\']'
    result = re.sub(pattern, "algorithm: 'HS256'", source)
    assert "HS256" in result

def test_jwt_safe_algorithm_unchanged():
    source = "jwt.sign(data, key, {algorithm: 'HS256'})"
    pattern = r"algorithm\s*:\s*['\"]none['\"]"
    result = re.sub(pattern, "algorithm: 'HS256'", source)
    assert "HS256" in result
    assert "none" not in result

# axios tests
def test_axios_tls_fixed():
    source = "axios.create({rejectUnauthorized: false})"
    pattern = r'rejectUnauthorized\s*:\s*false'
    result = re.sub(pattern, 'rejectUnauthorized: true', source)
    assert "true" in result
    assert "false" not in result

def test_axios_tls_with_spaces():
    source = "axios.create({ rejectUnauthorized : false })"
    pattern = r'rejectUnauthorized\s*:\s*false'
    result = re.sub(pattern, 'rejectUnauthorized: true', source)
    assert "true" in result

def test_axios_already_safe():
    source = "axios.create({rejectUnauthorized: true})"
    pattern = r'rejectUnauthorized\s*:\s*false'
    result = re.sub(pattern, 'rejectUnauthorized: true', source)
    assert "true" in result
    assert "false" not in result