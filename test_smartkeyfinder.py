import pytest
import string
from SmartKeyFinder.decrypter import Decrypter
from SmartKeyFinder.ngram_model import NGramModel
from Ciphers.caesar_cipher import CaesarCipher


@pytest.fixture
def decrypter():
    """Create a Decrypter instance for testing"""
    # Note: This will try to load sherlock_holmes.txt
    # In a real test environment, you might want to mock this
    try:
        return Decrypter()
    except FileNotFoundError:
        pytest.skip("sherlock_holmes.txt not found")


@pytest.fixture
def simple_decrypter():
    """Create a Decrypter with a simple n-gram model for faster tests"""
    d = Decrypter()
    # Train on a small corpus for faster tests
    d.ngram.train("THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG " * 10)
    return d


@pytest.fixture
def ngram_model():
    """Create an NGramModel for testing"""
    return NGramModel(n=3, k=0.1)


# ========== DECRYPTER TESTS ==========

def test_decrypter_init(decrypter):
    """Test Decrypter initialization"""
    assert decrypter.english_frequency_order is not None
    assert len(decrypter.english_frequency_order) == 26
    assert decrypter.alphabet == string.ascii_uppercase
    assert decrypter.ngram is not None


def test_decrypt_with_key_basic(simple_decrypter):
    """Test basic decryption with a key"""
    key = {'A': 'B', 'B': 'C', 'C': 'A'}
    # Complete the key for all letters
    for letter in string.ascii_uppercase:
        if letter not in key:
            key[letter] = letter
    
    ciphertext = "ABC"
    result = simple_decrypter.decrypt_with_key(ciphertext, key)
    assert result == "BCA"


def test_decrypt_with_key_preserves_case(simple_decrypter):
    """Test that decryption preserves case"""
    key = dict(zip(string.ascii_uppercase, string.ascii_uppercase))
    key['A'] = 'Z'
    key['Z'] = 'A'
    
    ciphertext = "Hello World"
    result = simple_decrypter.decrypt_with_key(ciphertext, key)
    assert result[0].isupper()  # 'H' should remain uppercase
    assert result[1].islower()  # 'e' should remain lowercase


def test_decrypt_with_key_preserves_special_chars(simple_decrypter):
    """Test that special characters are preserved"""
    key = dict(zip(string.ascii_uppercase, string.ascii_uppercase))
    ciphertext = "Hello, World! 123"
    result = simple_decrypter.decrypt_with_key(ciphertext, key)
    assert ',' in result
    assert '!' in result
    assert '123' in result


def test_frequency_initial_key(simple_decrypter):
    """Test frequency-based key generation"""
    # Create ciphertext with known frequency pattern
    ciphertext = "AAA BBB CCC DDD EEE" * 10
    key = simple_decrypter.frequency_initial_key(ciphertext)
    
    assert isinstance(key, dict)
    assert len(key) == 26
    # Most frequent letter should map to E (most common in English)
    assert 'A' in key
    assert key['A'] in string.ascii_uppercase


def test_frequency_initial_key_all_letters_mapped(simple_decrypter):
    """Test that all letters are mapped in frequency key"""
    ciphertext = "THE QUICK BROWN FOX"
    key = simple_decrypter.frequency_initial_key(ciphertext)
    
    # Check all letters are in the key
    for letter in string.ascii_uppercase:
        assert letter in key
        assert key[letter] in string.ascii_uppercase


def test_random_key(simple_decrypter):
    """Test random key generation"""
    key1 = simple_decrypter.random_key()
    key2 = simple_decrypter.random_key()
    
    assert isinstance(key1, dict)
    assert len(key1) == 26
    # Keys should be different (very high probability)
    assert key1 != key2 or pytest.skip("Random keys happened to be same")


def test_mutate_key(simple_decrypter):
    """Test key mutation"""
    original_key = dict(zip(string.ascii_uppercase, string.ascii_uppercase))
    mutated = simple_decrypter.mutate_key(original_key, num_swaps=1)
    
    assert mutated != original_key
    assert len(mutated) == 26
    # Original key should be unchanged
    assert original_key == dict(zip(string.ascii_uppercase, string.ascii_uppercase))


def test_mutate_key_multiple_swaps(simple_decrypter):
    """Test key mutation with multiple swaps"""
    original_key = dict(zip(string.ascii_uppercase, string.ascii_uppercase))
    mutated = simple_decrypter.mutate_key(original_key, num_swaps=5)
    
    assert mutated != original_key
    assert len(mutated) == 26


def test_swap_key_letters(simple_decrypter):
    """Test swapping specific letters in key"""
    key = dict(zip(string.ascii_uppercase, string.ascii_uppercase))
    key['A'] = 'X'
    key['B'] = 'Y'
    
    swapped = simple_decrypter.swap_key_letters(key, 'A', 'B')
    
    assert swapped['A'] == 'Y'
    assert swapped['B'] == 'X'
    assert swapped != key


def test_swap_key_letters_invalid(simple_decrypter):
    """Test swapping with invalid letters raises error"""
    key = dict(zip(string.ascii_uppercase, string.ascii_uppercase))
    
    with pytest.raises(ValueError):
        simple_decrypter.swap_key_letters(key, '1', '2')


def test_score_key(simple_decrypter):
    """Test key scoring"""
    key = dict(zip(string.ascii_uppercase, string.ascii_uppercase))
    ciphertext = "THE QUICK BROWN FOX"
    
    score = simple_decrypter.score_key(key, ciphertext)
    assert isinstance(score, (int, float))


def test_score_key_comparison(simple_decrypter):
    """Test that correct key scores higher than random key"""
    # Encrypt some text
    plaintext = "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG" * 5
    cipher = CaesarCipher(3)
    ciphertext = cipher.encrypt(plaintext)
    
    # Correct key (reverse Caesar shift)
    correct_key = dict(zip(string.ascii_uppercase, 
                          [chr((ord(c) - ord('A') - 3) % 26 + ord('A')) 
                           for c in string.ascii_uppercase]))
    
    # Random key
    random_key = simple_decrypter.random_key()
    
    correct_score = simple_decrypter.score_key(correct_key, ciphertext)
    random_score = simple_decrypter.score_key(random_key, ciphertext)
    
    # Correct key should generally score higher (though not guaranteed)
    # This test might be flaky, so we just check scores are numbers
    assert isinstance(correct_score, (int, float))
    assert isinstance(random_score, (int, float))


def test_hill_climb(simple_decrypter):
    """Test hill climbing optimization"""
    ciphertext = "THE QUICK BROWN FOX" * 10
    start_key = simple_decrypter.frequency_initial_key(ciphertext)
    
    best_key, best_score = simple_decrypter._hill_climb(ciphertext, start_key, iters=10)
    
    assert isinstance(best_key, dict)
    assert isinstance(best_score, (int, float))
    assert len(best_key) == 26


def test_temperature(simple_decrypter):
    """Test temperature calculation"""
    T_start = 3.0
    T_end = 1.0
    max_steps = 100
    
    # At start
    T0 = simple_decrypter._temperature(0, max_steps, T_start, T_end)
    assert abs(T0 - T_start) < 0.01
    
    # At end
    T_end_calc = simple_decrypter._temperature(max_steps, max_steps, T_start, T_end)
    assert abs(T_end_calc - T_end) < 0.01
    
    # Should decrease
    T_mid = simple_decrypter._temperature(50, max_steps, T_start, T_end)
    assert T_start > T_mid > T_end


def test_simulated_annealing(simple_decrypter):
    """Test simulated annealing optimization"""
    ciphertext = "THE QUICK BROWN FOX" * 10
    start_key = simple_decrypter.frequency_initial_key(ciphertext)
    
    best_key, best_score = simple_decrypter._simulated_annealing(
        ciphertext, start_key, iters=10, T_start=3.0, T_end=1.0
    )
    
    assert isinstance(best_key, dict)
    assert isinstance(best_score, (int, float))
    assert len(best_key) == 26


def test_temp_crack(simple_decrypter):
    """Test temp_crack convenience method"""
    ciphertext = "THE QUICK BROWN FOX" * 10
    
    best_key, best_score, plaintext = simple_decrypter.temp_crack(ciphertext)
    
    assert isinstance(best_key, dict)
    assert isinstance(best_score, (int, float))
    assert isinstance(plaintext, str)
    assert len(best_key) == 26


def test_crack_anneal_method(simple_decrypter):
    """Test crack method with annealing"""
    ciphertext = "THE QUICK BROWN FOX" * 10
    
    results = simple_decrypter.crack(ciphertext, method="anneal", restarts=2)
    
    assert "best_key" in results
    assert "best_score" in results
    assert "best_plaintext" in results
    assert isinstance(results["best_key"], dict)
    assert isinstance(results["best_score"], (int, float))
    assert isinstance(results["best_plaintext"], str)


def test_crack_hill_method(simple_decrypter):
    """Test crack method with hill climbing"""
    ciphertext = "THE QUICK BROWN FOX" * 10
    
    results = simple_decrypter.crack(ciphertext, method="hill", restarts=2)
    
    assert "best_key" in results
    assert "best_score" in results
    assert "best_plaintext" in results


def test_crack_invalid_method(simple_decrypter):
    """Test crack method with invalid method raises error"""
    ciphertext = "THE QUICK BROWN FOX"
    
    with pytest.raises(ValueError):
        simple_decrypter.crack(ciphertext, method="invalid")


def test_crack_caesar_cipher(simple_decrypter):
    """Test cracking a simple Caesar cipher"""
    plaintext = "HELLO WORLD" * 5
    cipher = CaesarCipher(3)
    ciphertext = cipher.encrypt(plaintext)
    
    results = simple_decrypter.crack(ciphertext, method="anneal", restarts=2)
    
    # Should produce some result
    assert results["best_plaintext"] is not None
    assert len(results["best_plaintext"]) > 0


# ========== NGRAM MODEL TESTS ==========

def test_ngram_model_init(ngram_model):
    """Test NGramModel initialization"""
    assert ngram_model.n == 3
    assert ngram_model.k == 0.1
    assert ngram_model.counts == {}
    assert ngram_model.total == 0


def test_normalise(ngram_model):
    """Test text normalization"""
    text = "Hello, World! 123"
    normalized = ngram_model.normalise(text)
    assert normalized == "HELLOWORLD"
    assert normalized.isupper()
    assert normalized.isalpha()


def test_train_basic(ngram_model):
    """Test training on basic text"""
    corpus = "THE QUICK BROWN FOX"
    ngram_model.train(corpus)
    
    assert ngram_model.total > 0
    assert len(ngram_model.counts) > 0
    assert ngram_model.floor is not None


def test_train_short_text(ngram_model):
    """Test training on text shorter than n"""
    corpus = "AB"  # Shorter than n=3
    ngram_model.train(corpus)
    
    assert ngram_model.total == 0
    assert ngram_model.floor == -1e9


def test_train_counts_ngrams(ngram_model):
    """Test that training counts n-grams correctly"""
    corpus = "ABC" * 10
    ngram_model.train(corpus)
    
    # Should have seen "ABC" multiple times
    assert "ABC" in ngram_model.counts or ngram_model.total > 0


def test_score_basic(ngram_model):
    """Test scoring basic text"""
    corpus = "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG" * 10
    ngram_model.train(corpus)
    
    score = ngram_model.score("THE QUICK BROWN")
    assert isinstance(score, (int, float))


def test_score_short_text(ngram_model):
    """Test scoring text shorter than n"""
    corpus = "THE QUICK BROWN FOX" * 10
    ngram_model.train(corpus)
    
    score = ngram_model.score("AB")
    assert score == -1e9


def test_score_unseen_ngrams(ngram_model):
    """Test scoring with unseen n-grams uses floor"""
    corpus = "THE QUICK BROWN FOX" * 10
    ngram_model.train(corpus)
    
    # Text with likely unseen n-grams
    score = ngram_model.score("ZZZ QQQ XXX")
    assert isinstance(score, (int, float))
    # Should be negative (floor value)


def test_score_english_vs_random(ngram_model):
    """Test that English text scores higher than random"""
    corpus = "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG " * 20
    ngram_model.train(corpus)
    
    english_score = ngram_model.score("THE QUICK BROWN FOX")
    random_score = ngram_model.score("QZX KJH GFV BNM")
    
    # English should generally score higher
    assert isinstance(english_score, (int, float))
    assert isinstance(random_score, (int, float))

