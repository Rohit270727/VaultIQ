import pytest
from strength_checker import check_strength, calculate_entropy
from crypto_utils import derive_key, encrypt_password, decrypt_password
import os

def test_weak_password_detected():
    strength, entropy, suggestions = check_strength("1234")
    assert strength == "Weak"

def test_strong_password_detected():
    strength, entropy, suggestions = check_strength("Xk9#mQ2$vLp8!nR")
    assert strength == "Strong"

def test_entropy_increases_with_complexity():
    weak_entropy = calculate_entropy("aaaaaa")
    strong_entropy = calculate_entropy("aA1!aA1!")
    assert strong_entropy > weak_entropy

def test_encrypt_decrypt_roundtrip():
    key = derive_key("master_password_123", os.urandom(16))
    original = "MySecretPassword!23"
    encrypted = encrypt_password(original, key)
    decrypted = decrypt_password(encrypted, key)
    assert decrypted == original

def test_encrypted_password_is_not_plaintext():
    key = derive_key("master_password_123", os.urandom(16))
    encrypted = encrypt_password("hello123", key)
    assert encrypted != b"hello123"
