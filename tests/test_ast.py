import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'spirit'))

from ast_engine.extractors import JSExtractor

extractor = JSExtractor()

# bcrypt extraction
def test_bcrypt_low_rounds_detected():
    source = "bcrypt.hashSync(password, 4)"
    results = extractor.extract_bcrypt(source)
    assert len(results) == 1
    assert results[0]["value"] == 4
    assert results[0]["library"] == "bcrypt"

def test_bcrypt_safe_rounds_detected():
    source = "bcrypt.hashSync(password, 12)"
    results = extractor.extract_bcrypt(source)
    assert len(results) == 1
    assert results[0]["value"] == 12

def test_bcrypt_not_present():
    source = "const x = require('express')"
    results = extractor.extract_bcrypt(source)
    assert len(results) == 0

# jwt extraction
def test_jwt_algorithm_none_detected():
    source = "jwt.sign(data, key, {algorithm: 'none'})"
    results = extractor.extract_jwt(source)
    assert len(results) == 1
    assert results[0]["value"] == "none"

def test_jwt_double_quotes_detected():
    source = 'jwt.sign(data, key, {algorithm: "none"})'
    results = extractor.extract_jwt(source)
    assert len(results) == 1

def test_jwt_safe_algorithm_not_flagged():
    source = "jwt.sign(data, key, {algorithm: 'HS256'})"
    results = extractor.extract_jwt(source)
    assert len(results) == 0

# axios extraction
def test_axios_tls_disabled_detected():
    source = "axios.create({rejectUnauthorized: false})"
    results = extractor.extract_axios(source)
    assert len(results) == 1
    assert results[0]["value"] == "false"

def test_axios_safe_not_flagged():
    source = "axios.create({rejectUnauthorized: true})"
    results = extractor.extract_axios(source)
    assert len(results) == 0

# import extraction
def test_require_imports_extracted():
    source = """
    const bcrypt = require('bcrypt')
    const jwt = require('jsonwebtoken')
    const axios = require('axios')
    """
    imports = extractor.extract_imports(source)
    assert "bcrypt" in imports
    assert "jsonwebtoken" in imports
    assert "axios" in imports

def test_es6_imports_extracted():
    source = """
    import bcrypt from 'bcrypt'
    import jwt from 'jsonwebtoken'
    """
    imports = extractor.extract_imports(source)
    assert "bcrypt" in imports
    assert "jsonwebtoken" in imports

def test_line_numbers_correct():
    source = "const x = 1\nbcrypt.hashSync(password, 4)"
    results = extractor.extract_bcrypt(source)
    assert results[0]["line"] == 2