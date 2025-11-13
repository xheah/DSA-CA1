import pytest

from Ciphers.keyword_cipher import KeywordCipher
from Ciphers.caesar_cipher import CaesarCipher
from Ciphers.vigenere_cipher import VigenereCipher
from Ciphers.affine_cipher import AffineCipher

def test_kc_correct_cipher():
    cypher = KeywordCipher('ZEBRAS')
    assert cypher.get_keyword_cipher() == 'ZEBRASCDFGHIJKLMNOPQTUVWXY'
    assert cypher.encrypt('I want to eat your pancreas.\nYour Name.') == "F vzkq ql azq xlto mzkboazp.\nXlto Kzja."
    assert cypher.decrypt('F vzkq ql azq xlto mzkboazp.\nXlto Kzja.') == 'I want to eat your pancreas.\nYour Name.'

def test_keyword_cipher_special_chars():
    """Test that special chars in keyword are filtered"""
    cipher = KeywordCipher('KEY123!WORD')
    assert cipher.get_keyword() == 'KEYWORD'
    assert len(cipher.get_keyword_cipher()) == 26

def test_keyword_cipher_round_trip():
    """Test encrypt -> decrypt returns original"""
    cipher = KeywordCipher('TEST')
    original = "Hello World 123!"
    encrypted = cipher.encrypt(original)
    decrypted = cipher.decrypt(encrypted)
    assert decrypted == original

def test_keyword_cipher_case_preservation():
    """Test that case is preserved"""
    cipher = KeywordCipher('TEST')
    text = "HeLLo WoRLd"
    encrypted = cipher.encrypt(text)
    decrypted = cipher.decrypt(encrypted)
    assert decrypted == text
    # Verify case is preserved in encrypted text
    assert encrypted[0].isupper() == text[0].isupper()

def test_keyword_cipher_duplicate_letters():
    """Test keyword with duplicate letters"""
    cipher = KeywordCipher('APPLE')
    cipher_alphabet = cipher.get_keyword_cipher()
    # Verify 'P' appears only once in cipher alphabet
    assert cipher_alphabet.count('P') == 1
    # Verify keyword letters appear first
    assert cipher_alphabet.startswith('APLE')

def test_keyword_cipher_single_letter():
    """Test with single letter keyword"""
    cipher = KeywordCipher('A')
    assert cipher.get_keyword_cipher().startswith('A')
    encrypted = cipher.encrypt('HELLO')
    decrypted = cipher.decrypt(encrypted)
    assert decrypted == 'HELLO'

def test_keyword_cipher_mixed_case_keyword():
    """Test keyword with mixed case (should normalize to uppercase)"""
    cipher1 = KeywordCipher('Test')
    cipher2 = KeywordCipher('TEST')
    assert cipher1.get_keyword() == cipher2.get_keyword()
    assert cipher1.get_keyword_cipher() == cipher2.get_keyword_cipher()

def test_keyword_cipher_empty_string():
    """Test encrypting/decrypting empty string"""
    cipher = KeywordCipher('TEST')
    assert cipher.encrypt('') == ''
    assert cipher.decrypt('') == ''

def test_keyword_cipher_special_characters():
    """Test that special characters are preserved"""
    cipher = KeywordCipher('TEST')
    text = "Hello, World! 123\nNew line."
    encrypted = cipher.encrypt(text)
    decrypted = cipher.decrypt(encrypted)
    assert decrypted == text
    # Verify special chars are preserved
    assert ',' in encrypted and ',' in decrypted
    assert '!' in encrypted and '!' in decrypted
    assert '123' in encrypted and '123' in decrypted

def test_keyword_cipher_all_uppercase():
    """Test all uppercase text"""
    cipher = KeywordCipher('TEST')
    text = "HELLO WORLD"
    encrypted = cipher.encrypt(text)
    decrypted = cipher.decrypt(encrypted)
    assert decrypted == text

def test_keyword_cipher_all_lowercase():
    """Test all lowercase text"""
    cipher = KeywordCipher('TEST')
    text = "hello world"
    encrypted = cipher.encrypt(text)
    decrypted = cipher.decrypt(encrypted)
    assert decrypted == text

def test_keyword_cipher_multiple_rounds():
    """Test multiple encrypt/decrypt cycles"""
    cipher = KeywordCipher('TEST')
    original = "Hello World"
    encrypted = original
    # Encrypt multiple times
    for _ in range(3):
        encrypted = cipher.encrypt(encrypted)
    # Decrypt multiple times
    decrypted = encrypted
    for _ in range(3):
        decrypted = cipher.decrypt(decrypted)
    assert decrypted == original

def test_keyword_cipher_long_keyword():
    """Test with very long keyword"""
    cipher = KeywordCipher('SUPERCALIFRAGILISTICEXPIALIDOCIOUS')
    cipher_alphabet = cipher.get_keyword_cipher()
    # Should still be 26 characters
    assert len(cipher_alphabet) == 26
    # Should work correctly
    text = "TEST"
    encrypted = cipher.encrypt(text)
    decrypted = cipher.decrypt(encrypted)
    assert decrypted == text

def test_keyword_cipher_get_keyword():
    """Test get_keyword method"""
    cipher = KeywordCipher('Test123')
    assert cipher.get_keyword() == 'TEST'

def test_keyword_cipher_preserves_formatting():
    """Test that formatting (newlines, tabs, spaces) is preserved"""
    cipher = KeywordCipher('TEST')
    text = "Line 1\nLine 2\n\tIndented"
    encrypted = cipher.encrypt(text)
    decrypted = cipher.decrypt(encrypted)
    assert decrypted == text
    assert '\n' in encrypted and '\t' in encrypted


def test_caesar_cipher_round_trip():
    cipher = CaesarCipher(3)
    text = "Hello World!"
    encrypted = cipher.encrypt(text)
    assert encrypted != text
    decrypted = cipher.decrypt(encrypted)
    assert decrypted == text


def test_caesar_cipher_large_shift_wraps():
    cipher = CaesarCipher(55)  # 55 % 26 == 3
    text = "ABC xyz"
    encrypted = cipher.encrypt(text)
    assert encrypted == "XYZ uvw"
    assert cipher.decrypt(encrypted) == text


def test_vigenere_cipher_round_trip():
    cipher = VigenereCipher('lemon')
    text = "Attack at dawn!"
    encrypted = cipher.encrypt(text)
    assert encrypted != text
    decrypted = cipher.decrypt(encrypted)
    assert decrypted == text


def test_vigenere_cipher_preserves_case_and_nonalpha():
    cipher = VigenereCipher('MiXeDCase123')
    text = "Hello, World 123!"
    encrypted = cipher.encrypt(text)
    decrypted = cipher.decrypt(encrypted)
    assert decrypted == text
    # Ensure case preserved in encrypted text for letters
    for original_char, encrypted_char in zip(text, encrypted):
        if original_char.isalpha():
            assert original_char.isupper() == encrypted_char.isupper()


def test_vigenere_cipher_invalid_key():
    with pytest.raises(ValueError):
        VigenereCipher('1234!@')


def test_affine_cipher_round_trip():
    cipher = AffineCipher([5, 8])
    text = "Affine Cipher Test!"
    encrypted = cipher.encrypt(text)
    assert encrypted != text
    decrypted = cipher.decrypt(encrypted)
    assert decrypted == text


def test_affine_cipher_invalid_key():
    with pytest.raises(ValueError):
        AffineCipher([13, 5])  # gcd(13, 26) > 1