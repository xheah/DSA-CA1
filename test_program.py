from pathlib import Path

import pytest

from program import Program
from Ciphers.keyword_cipher import KeywordCipher
from Ciphers.caesar_cipher import CaesarCipher


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
