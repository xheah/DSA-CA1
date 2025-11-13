from letterFreq import LFD
from Ciphers.keyword_cipher import KeywordCipher

def test_fd():
    lfd = LFD("I want to eat your pancreas. Your Name.")
    assert lfd.get_fd() ==  {
        'A': 5, 'B': 0, 'C': 1, 'D': 0, 'E': 3, 'F': 0, 'G': 0,
        'H': 0, 'I': 1, 'J': 0, 'K': 0, 'L': 0, 'M': 1, 'N': 3,
        'O': 3, 'P': 1, 'Q': 0, 'R': 3, 'S': 1, 'T': 3, 'U': 2,
        'V': 0, 'W': 1, 'X': 0, 'Y': 2, 'Z': 0
    }
    
    assert lfd.calculate_percentages() == {
        'A': 16.67, 'B': 0.00, 'C': 3.33, 'D': 0.00, 'E': 10.00, 'F': 0.00, 'G': 0.00, 'H': 0.00,
        'I': 3.33, 'J': 0.00, 'K': 0.00, 'L': 0.00, 'M': 3.33, 'N': 10.00, 'O': 10.00, 'P': 3.33,
        'Q': 0.00, 'R': 10.00, 'S': 3.33, 'T': 10.00, 'U': 6.67, 'V': 0.00, 'W': 3.33, 'X': 0.00,
        'Y': 6.67, 'Z': 0.00
    }

    assert lfd.calc_top5() == [('A', 16.67), ('E', 10.00), ('N', 10.00), ('O', 10.00), ('R', 10.00)]

def test_lfd_empty_text():
    """Test LFD with empty string"""
    lfd = LFD("")
    fd = lfd.get_fd()
    # All frequencies should be 0
    assert all(count == 0 for count in fd.values())
    # Percentages should all be 0
    fdp = lfd.get_fdp()
    assert all(pct == 0.0 or pct == 0 for pct in fdp.values())

def test_lfd_no_letters():
    """Test text with no alphabetic characters"""
    lfd = LFD("123!@#$%^&*()")
    fd = lfd.get_fd()
    # All frequencies should be 0
    assert all(count == 0 for count in fd.values())
    fdp = lfd.get_fdp()
    # All percentages should be 0
    assert all(pct == 0.0 or pct == 0 for pct in fdp.values())

def test_lfd_calc_percentages_zero_division():
    """Test percentages with empty text (should handle gracefully)"""
    lfd = LFD("")
    fdp = lfd.get_fdp()
    # Should return all zeros, not crash
    assert isinstance(fdp, dict)
    assert len(fdp) == 26

def test_lfd_calc_top5_less_than_five():
    """Test top5 with fewer than 5 unique letters"""
    lfd = LFD("AAA BBB")
    top5 = lfd.get_top5()
    # Should return exactly 5 items (A, B, and 3 letters with 0 frequency)
    assert len(top5) == 5
    # A and B should be in top5 with highest frequencies
    top5_letters = [letter for letter, freq in top5]
    assert 'A' in top5_letters
    assert 'B' in top5_letters
    # All non-zero frequency letters should be A or B
    non_zero = [(letter, freq) for letter, freq in top5 if freq > 0]
    assert all(letter in ['A', 'B'] for letter, _ in non_zero)
    assert len(non_zero) == 2  # Only A and B have non-zero frequency

def test_lfd_calc_top5_exactly_five():
    """Test top5 with exactly 5 unique letters"""
    lfd = LFD("A B C D E")
    top5 = lfd.get_top5()
    assert len(top5) == 5

def test_lfd_calc_top5_ties():
    """Test top5 with ties in frequency (should sort alphabetically)"""
    lfd = LFD("A A B B C C D D E E")
    top5 = lfd.get_top5()
    # Should have 5 items, sorted by frequency (desc) then alphabetically
    assert len(top5) == 5
    # All should have same frequency
    frequencies = [freq for _, freq in top5]
    assert len(set(frequencies)) == 1

def test_lfd_single_character():
    """Test with single character"""
    lfd = LFD("A")
    fd = lfd.get_fd()
    assert fd['A'] == 1
    assert sum(fd.values()) == 1
    fdp = lfd.get_fdp()
    assert fdp['A'] == 100.0

def test_lfd_special_characters_preserved():
    """Test that special characters don't affect letter counting"""
    lfd = LFD("Hello, World! 123\nNew\tLine.")
    fd = lfd.get_fd()
    # Should count letters correctly, ignoring special chars
    assert fd['H'] == 1
    assert fd['E'] == 3
    assert fd['L'] == 4

def test_lfd_get_eng_freq():
    """Test English frequency getter"""
    lfd = LFD("TEST")
    eng_freq = lfd.get_eng_freq()
    assert isinstance(eng_freq, dict)
    assert 'E' in eng_freq
    assert eng_freq['E'] == 12.7  # E is most common in English

def test_lfd_str_contains_data():
    """Test that __str__ returns a non-empty visualisation"""
    lfd = LFD("AAAA BBBB CCCC")
    output = str(lfd)
    assert len(output) > 0
    # Should contain letter labels
    assert 'A' in output or 'B' in output or 'C' in output

def test_infer_keyword_valid(tmp_path, monkeypatch):
    """Test keyword inference with valid keyword"""
    # Create a test dictionary file
    dict_file = tmp_path / 'dictionary.txt'
    dict_file.write_text('hello\nworld\ntest\nthis\nis\nvalid')
    
    # Create encrypted text
    cipher = KeywordCipher('TEST')
    original = "hello world this is a test"
    encrypted = cipher.encrypt(original)
    
    # Change to test directory
    import os
    original_dir = os.getcwd()
    try:
        os.chdir(tmp_path)
        lfd = LFD(encrypted)
        keywords = ['TEST', 'WRONG', 'OTHER']
        result = lfd.infer_keyword(keywords)
        assert result == 'TEST'
    finally:
        os.chdir(original_dir)

def test_infer_keyword_no_match(tmp_path, monkeypatch):
    """Test when no keyword scores above threshold"""
    # Create a test dictionary file
    dict_file = tmp_path / 'dictionary.txt'
    dict_file.write_text('hello\nworld')
    
    # Create encrypted text with random keyword
    cipher = KeywordCipher('XYZ')
    encrypted = cipher.encrypt("gibberish xyz abc random")
    
    import os
    original_dir = os.getcwd()
    try:
        os.chdir(tmp_path)
        lfd = LFD(encrypted)
        keywords = ['WRONG1', 'WRONG2', 'WRONG3']
        result = lfd.infer_keyword(keywords)
        # Should return message if no keyword scores above 0.10
        assert result == 'no keyword found'
    finally:
        os.chdir(original_dir)

def test_infer_keyword_empty_list(tmp_path):
    """Test with empty keyword list"""
    dict_file = tmp_path / 'dictionary.txt'
    dict_file.write_text('hello\nworld')
    
    import os
    original_dir = os.getcwd()
    try:
        os.chdir(tmp_path)
        lfd = LFD("test text")
        result = lfd.infer_keyword([])
        assert result == ''
    finally:
        os.chdir(original_dir)

def test_infer_keyword_whitespace_keywords(tmp_path):
    """Test with keywords containing whitespace"""
    dict_file = tmp_path / 'dictionary.txt'
    dict_file.write_text('hello\nworld\ntest')
    
    cipher = KeywordCipher('TEST')
    encrypted = cipher.encrypt("hello world test")
    
    import os
    original_dir = os.getcwd()
    try:
        os.chdir(tmp_path)
        lfd = LFD(encrypted)
        keywords = [' TEST ', '  TEST  ', 'TEST']
        result = lfd.infer_keyword(keywords)
        # Should find TEST even with whitespace
        assert result.strip() == 'TEST' or result == 'TEST'
    finally:
        os.chdir(original_dir)

def test_lfd_percentages_sum():
    """Test that percentages sum to approximately 100"""
    lfd = LFD("This is a test with multiple letters")
    fdp = lfd.get_fdp()
    total = sum(fdp.values())
    # Should be approximately 100 (allowing for rounding)
    assert 99.0 <= total <= 100.1

def test_lfd_all_letters_same_frequency():
    """Test when all letters appear equally"""
    # Create text with one of each letter
    text = ''.join(chr(i) for i in range(ord('A'), ord('Z')+1))
    lfd = LFD(text.lower())
    fd = lfd.get_fd()
    # Each letter should appear once
    assert all(count == 1 for count in fd.values())


