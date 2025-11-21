from pathlib import Path
import string
import threading
import time

import pytest

from program import Program
from Ciphers.keyword_cipher import KeywordCipher
from Ciphers.caesar_cipher import CaesarCipher
from SmartKeyFinder.decrypter import Decrypter


@pytest.fixture
def program(monkeypatch):
    prog = Program()
    monkeypatch.setattr(Program, '_wait_for_continue', lambda self: None)
    return prog


def test_handle_encrypt_decrypt_encrypts_file(program, tmp_path, monkeypatch):
    output_path = tmp_path / 'encrypted.txt'
    plaintext = 'Hello World'
    keyword = 'APPLE'

    monkeypatch.setattr(program, 'encrypt_or_decrypt', lambda: 'E')
    monkeypatch.setattr(program, 'get_file_ED', lambda _: plaintext)
    monkeypatch.setattr(program, 'get_keyword', lambda: keyword)
    monkeypatch.setattr(program, 'get_output_file', lambda: str(output_path))

    program._handle_encrypt_decrypt()

    expected = KeywordCipher(keyword).encrypt(plaintext)
    assert output_path.read_text() == expected


def test_handle_encrypt_decrypt_decrypts_file(program, tmp_path, monkeypatch):
    output_path = tmp_path / 'decrypted.txt'
    keyword = 'BANANA'
    plaintext = 'Secret Message'
    encrypted = KeywordCipher(keyword).encrypt(plaintext)

    monkeypatch.setattr(program, 'encrypt_or_decrypt', lambda: 'D')
    monkeypatch.setattr(program, 'get_file_ED', lambda _: encrypted)
    monkeypatch.setattr(program, 'get_keyword', lambda: keyword)
    monkeypatch.setattr(program, 'get_output_file', lambda: str(output_path))

    program._handle_encrypt_decrypt()

    assert output_path.read_text() == plaintext


def test_handle_frequency_distribution_prints(program, monkeypatch, capsys):
    monkeypatch.setattr(program, 'get_input_file', lambda: 'AAA BBB')

    program._handle_frequency_distribution()

    captured = capsys.readouterr()
    assert 'A' in captured.out


def test_handle_infer_keyword_decrypts_when_user_accepts(program, tmp_path, monkeypatch):
    keyword = 'APPLE'
    plaintext = 'this is a secret'
    encrypted = KeywordCipher(keyword).encrypt(plaintext)
    output_path = tmp_path / 'result.txt'

    monkeypatch.setattr(program, 'get_input_file', lambda: encrypted)
    monkeypatch.setattr(program, 'get_keyword_file', lambda: 'APPLE\nOTHER')
    monkeypatch.setattr(program, 'get_output_file', lambda: str(output_path))
    monkeypatch.setattr('letterFreq.LFD.infer_keyword', lambda self, _: keyword)
    monkeypatch.setattr('builtins.input', lambda prompt='': 'Y')

    program._handle_infer_keyword()

    assert output_path.read_text() == plaintext


def test_handle_infer_keyword_no_keyword(program, monkeypatch, capsys):
    monkeypatch.setattr(program, 'get_input_file', lambda: 'ciphertext')
    monkeypatch.setattr(program, 'get_keyword_file', lambda: 'ONE\nTWO')
    monkeypatch.setattr('letterFreq.LFD.infer_keyword', lambda self, _: '')

    program._handle_infer_keyword()

    captured = capsys.readouterr()
    assert 'No keyword was found' in captured.out


def test_handle_batch_decryption_creates_outputs(program, tmp_path, monkeypatch):
    folder_path = tmp_path / 'case'
    folder_path.mkdir()
    keyword_file = folder_path / 'keywords.txt'
    keyword_file.write_text('APPLE\nOTHER')

    keyword = 'APPLE'
    cipher = KeywordCipher(keyword)
    originals = {
        'file1.txt': 'Hello World',
        'file2.txt': 'Another secret'
    }
    for name, text in originals.items():
        (folder_path / name).write_text(cipher.encrypt(text))

    monkeypatch.setattr(program, 'get_folder_name', lambda: folder_path)
    monkeypatch.setattr(program, 'get_keyword_list_file', lambda _: keyword_file)
    monkeypatch.setattr('letterFreq.LFD.infer_keyword', lambda self, _: keyword)

    program._handle_batch_decryption()

    for name, text in originals.items():
        output_file = folder_path / f'{Path(name).stem}_decr.txt'
        assert output_file.read_text() == text

    log_path = folder_path / 'log.txt'
    log_contents = log_path.read_text()
    for name in originals:
        assert Path(name).name in log_contents


def test_handle_batch_decryption_skips_when_no_keyword(program, tmp_path, monkeypatch, capsys):
    folder_path = tmp_path / 'case'
    folder_path.mkdir()
    keyword_file = folder_path / 'keywords.txt'
    keyword_file.write_text('APPLE')

    encrypted_file = folder_path / 'secret.txt'
    encrypted_file.write_text('encrypted data')

    monkeypatch.setattr(program, 'get_folder_name', lambda: folder_path)
    monkeypatch.setattr(program, 'get_keyword_list_file', lambda _: keyword_file)
    monkeypatch.setattr('letterFreq.LFD.infer_keyword', lambda self, _: 'no keyword found')

    program._handle_batch_decryption()

    captured = capsys.readouterr()
    assert 'no keyword found' in captured.out
    assert not (folder_path / 'secret_decr.txt').exists()
    assert (folder_path / 'log.txt').read_text() == ''


def test_handle_cipher_selection_keyword_cipher(program, tmp_path, monkeypatch):
    output_path = tmp_path / 'keyword_out.txt'
    plaintext = 'Attack at dawn'
    keyword = 'ORANGE'

    inputs = iter(['1'])
    monkeypatch.setattr('builtins.input', lambda prompt='': next(inputs))
    monkeypatch.setattr(program, 'get_keyword', lambda: keyword)
    monkeypatch.setattr(program, 'encrypt_or_decrypt', lambda: 'E')
    monkeypatch.setattr(program, 'get_file_ED', lambda _: plaintext)
    monkeypatch.setattr(program, 'get_output_file', lambda: str(output_path))

    program._handle_cipher_selection()

    expected = KeywordCipher(keyword).encrypt(plaintext)
    assert output_path.read_text() == expected


def test_handle_cipher_selection_caesar_cipher(program, tmp_path, monkeypatch):
    output_path = tmp_path / 'caesar_out.txt'
    plaintext = 'ABC xyz'
    shift = 5

    inputs = iter(['2'])
    monkeypatch.setattr('builtins.input', lambda prompt='': next(inputs))
    monkeypatch.setattr(program, 'get_caesar_shift', lambda: shift)
    monkeypatch.setattr(program, 'encrypt_or_decrypt', lambda: 'E')
    monkeypatch.setattr(program, 'get_file_ED', lambda _: plaintext)
    monkeypatch.setattr(program, 'get_output_file', lambda: str(output_path))

    program._handle_cipher_selection()

    expected = CaesarCipher(shift).encrypt(plaintext)
    assert output_path.read_text() == expected


# ========== NEW PROGRAM.PY METHOD TESTS ==========

def test_format_key_mapping(program):
    """Test key mapping formatting"""
    key_str = string.ascii_uppercase
    result = program.format_key_mapping(key_str)
    
    assert "CIPHER:" in result
    assert "PLAIN :" in result
    assert "A B C" in result
    assert len(result.split('\n')) == 2


def test_get_yn_valid_input(program, monkeypatch):
    """Test get_yn with valid Y input"""
    inputs = iter(['Y'])
    monkeypatch.setattr('builtins.input', lambda prompt='': next(inputs))
    
    result = program.get_yn('Test question')
    assert result == 'Y'


def test_get_yn_valid_n_input(program, monkeypatch):
    """Test get_yn with valid N input"""
    inputs = iter(['N'])
    monkeypatch.setattr('builtins.input', lambda prompt='': next(inputs))
    
    result = program.get_yn('Test question')
    assert result == 'N'


def test_get_yn_invalid_then_valid(program, monkeypatch):
    """Test get_yn with invalid then valid input"""
    inputs = iter(['invalid', 'maybe', 'Y'])
    monkeypatch.setattr('builtins.input', lambda prompt='': next(inputs))
    
    result = program.get_yn('Test question')
    assert result == 'Y'


def test_get_yn_case_insensitive(program, monkeypatch):
    """Test get_yn is case insensitive"""
    inputs = iter(['y', 'n'])
    monkeypatch.setattr('builtins.input', lambda prompt='': next(inputs))
    
    result1 = program.get_yn('Test question')
    result2 = program.get_yn('Test question')
    assert result1 == 'Y'
    assert result2 == 'N'


def test_get_crack_method_hill(program, monkeypatch):
    """Test get_crack_method returns hill for H"""
    inputs = iter(['H'])
    monkeypatch.setattr('builtins.input', lambda prompt='': next(inputs))
    
    result = program.get_crack_method()
    assert result == 'hill'


def test_get_crack_method_anneal(program, monkeypatch):
    """Test get_crack_method returns anneal for SA"""
    inputs = iter(['SA'])
    monkeypatch.setattr('builtins.input', lambda prompt='': next(inputs))
    
    result = program.get_crack_method()
    assert result == 'anneal'


def test_get_crack_method_invalid_then_valid(program, monkeypatch):
    """Test get_crack_method with invalid then valid input"""
    inputs = iter(['invalid', 'X', 'H'])
    monkeypatch.setattr('builtins.input', lambda prompt='': next(inputs))
    
    result = program.get_crack_method()
    assert result == 'hill'


def test_display_ngram_results(program, capsys):
    """Test display_ngram_results output"""
    results = {
        "best_key": dict(zip(string.ascii_uppercase, string.ascii_uppercase)),
        "best_score": 123.45,
        "best_plaintext": "THE QUICK BROWN FOX"
    }
    
    program.display_ngram_results(results)
    
    captured = capsys.readouterr()
    assert "N-GRAM DECRYPTION RESULT" in captured.out
    assert "123.45" in captured.out
    assert "CIPHER:" in captured.out
    assert "PLAIN :" in captured.out
    assert "THE QUICK BROWN FOX" in captured.out


def test_display_ngram_results_long_text(program, monkeypatch, capsys):
    """Test display_ngram_results with long text that gets truncated"""
    long_text = "THE QUICK BROWN FOX " * 100  # Very long text
    results = {
        "best_key": dict(zip(string.ascii_uppercase, string.ascii_uppercase)),
        "best_score": 123.45,
        "best_plaintext": long_text
    }
    
    # User chooses not to view full text
    inputs = iter(['N'])
    monkeypatch.setattr('builtins.input', lambda prompt='': next(inputs))
    
    program.display_ngram_results(results)
    
    captured = capsys.readouterr()
    assert "[...output truncated]" in captured.out


def test_display_ngram_results_empty_plaintext(program, capsys):
    """Test display_ngram_results with empty plaintext"""
    results = {
        "best_key": dict(zip(string.ascii_uppercase, string.ascii_uppercase)),
        "best_score": 0.0,
        "best_plaintext": ""
    }
    
    program.display_ngram_results(results)
    
    captured = capsys.readouterr()
    assert "[No Plaintext Produced]" in captured.out


def test_handle_ngram_decryption(program, tmp_path, monkeypatch, capsys):
    """Test _handle_ngram_decryption with full flow"""
    # Create a simple decrypter that doesn't require sherlock_holmes.txt
    ciphertext = "THE QUICK BROWN FOX" * 10
    
    input_file = tmp_path / 'ciphertext.txt'
    input_file.write_text(ciphertext)
    output_file = tmp_path / 'decrypted.txt'
    
    # Mock the decrypter to avoid file loading issues
    mock_results = {
        "best_key": dict(zip(string.ascii_uppercase, string.ascii_uppercase)),
        "best_score": 100.0,
        "best_plaintext": "DECRYPTED TEXT"
    }
    
    class MockDecrypter:
        def crack(self, text, method, restarts):
            return mock_results
    
    inputs = iter(['A', 'N'])  # Method: anneal, Don't save file
    monkeypatch.setattr('builtins.input', lambda prompt='': next(inputs))
    monkeypatch.setattr(program, 'get_input_file', lambda: ciphertext)
    monkeypatch.setattr(program, 'get_crack_method', lambda: 'anneal')
    monkeypatch.setattr('program.Decrypter', MockDecrypter)
    
    program._handle_ngram_decryption()
    
    captured = capsys.readouterr()
    assert "N-GRAM DECRYPTION RESULT" in captured.out or "DECRYPTED TEXT" in captured.out


def test_handle_ngram_decryption_saves_file(program, tmp_path, monkeypatch):
    """Test _handle_ngram_decryption saves file when user chooses Y"""
    ciphertext = "THE QUICK BROWN FOX" * 10
    output_file = tmp_path / 'decrypted.txt'
    
    mock_results = {
        "best_key": dict(zip(string.ascii_uppercase, string.ascii_uppercase)),
        "best_score": 100.0,
        "best_plaintext": "DECRYPTED TEXT"
    }
    
    class MockDecrypter:
        def crack(self, text, method, restarts):
            return mock_results
    
    inputs = iter(['A', 'Y'])  # Method: anneal, Save file
    monkeypatch.setattr('builtins.input', lambda prompt='': next(inputs))
    monkeypatch.setattr(program, 'get_input_file', lambda: ciphertext)
    monkeypatch.setattr(program, 'get_crack_method', lambda: 'anneal')
    monkeypatch.setattr(program, 'get_output_file', lambda: str(output_file))
    monkeypatch.setattr('program.Decrypter', MockDecrypter)
    
    program._handle_ngram_decryption()
    
    assert output_file.exists()
    assert output_file.read_text() == "DECRYPTED TEXT"


def test_loading_animation_stops(program):
    """Test loading animation stops when event is set"""
    stop_event = threading.Event()
    
    # Start animation in a thread
    thread = threading.Thread(
        target=program.loading_animation,
        args=(stop_event, 0.01),  # Fast delay for testing
        daemon=True
    )
    thread.start()
    
    # Let it run briefly
    time.sleep(0.1)
    
    # Stop it
    stop_event.set()
    thread.join(timeout=1.0)
    
    # Thread should have finished
    assert not thread.is_alive()
