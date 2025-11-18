import string
import random
import math
from typing import Dict
from letterFreq import LFD
from SmartKeyFinder.ngram_model import NGramModel
from Ciphers.caesar_cipher import CaesarCipher


class Decrypter:
    """
    Class for decrypting substitution ciphers using frequency analysis and key mutations.
    
    This class provides methods for breaking substitution ciphers using various
    optimization techniques including hill climbing and simulated annealing, with
    n-gram language models for scoring decryption quality.
    
    Attributes
    ----------
    english_frequency_order : list of str
        List of English letters ordered by frequency (most to least common).
    alphabet : str
        Uppercase alphabet string.
    ngram : NGramModel
        Trained n-gram model for scoring text quality.
    """
    
    def __init__(self):
        """
        Initialize Decrypter with English letter frequency order and n-gram model.
        
        Loads and trains an n-gram model on the Sherlock Holmes corpus for
        use in scoring decryption attempts.
        
        Notes
        -----
        The n-gram model is trained on 'sherlock_holmes.txt' which must be
        present in the working directory.
        """
        # English letter frequency order (most to least common)
        self.english_frequency_order = list("ETAOINSHRDLCUMWFGYPBVKJXQZ")
        self.alphabet = string.ascii_uppercase
        self.ngram = NGramModel()
        with open('sherlock_holmes.txt', 'r', encoding='utf-8') as f:
            corpus = f.read()
        self.ngram.train(corpus)
    
    def decrypt_with_key(self, ciphertext: str, key: Dict[str, str]) -> str:
        """
        Decrypt ciphertext using a substitution key.
        
        Parameters
        ----------
        ciphertext : str
            The encrypted text to decrypt.
        key : dict of {str: str}
            Dictionary mapping ciphertext letters (uppercase) to plaintext
            letters (uppercase). Keys are ciphertext letters, values are
            plaintext letters.
        
        Returns
        -------
        str
            Decrypted text with case and non-alphabetic characters preserved.
        """
        output = []
        for ch in ciphertext:
            ch_upper = ch.upper()
            if ch_upper in self.alphabet:
                # Get plaintext letter from key, preserve original case
                # print(key)
                plaintext_char = key.get(ch_upper, ch_upper)  # Default to original if not in key
                output.append(plaintext_char if ch.isupper() else plaintext_char.lower())
            else:
                output.append(ch)
        return ''.join(output)

    def frequency_initial_key(self, ciphertext: str) -> Dict[str, str]:
        """
        Generate initial decryption key using frequency analysis.
        
        Maps most frequent ciphertext letters to most frequent English letters
        based on letter frequency distributions. This provides a good starting
        point for optimization algorithms.
        
        Parameters
        ----------
        ciphertext : str
            The encrypted text to analyze for letter frequencies.
        
        Returns
        -------
        dict of {str: str}
            Dictionary mapping ciphertext letters (uppercase) to plaintext
            letters (uppercase). All 26 letters are mapped, with unmapped
            letters assigned to remaining English frequency letters.
        """
        lfd = LFD(ciphertext)
        frequency_dist = lfd.get_fd()
        
        # Sort by frequency (descending), then alphabetically for ties
        sorted_frequency_dist = sorted(
            frequency_dist.items(), 
            key=lambda x: (-x[1], x[0])
        )
        ciphertext_frequent_letters = [letter for letter, _ in sorted_frequency_dist]
        
        # Create mapping: ciphertext letter -> English frequency letter
        # Only map as many letters as we have in both lists
        mapping_length = min(len(ciphertext_frequent_letters), len(self.english_frequency_order))
        cipher_to_plain = dict(
            zip(
                ciphertext_frequent_letters[:mapping_length],
                self.english_frequency_order[:mapping_length]
            )
        )

        for letter in self.alphabet:
            if letter not in cipher_to_plain:
                # Find an unused English letter
                for eng_letter in self.english_frequency_order:
                    if eng_letter not in cipher_to_plain.values():
                        cipher_to_plain[letter] = eng_letter
                        break
                else:
                    # If all English letters are used, map to itself
                    cipher_to_plain[letter] = letter
        
        return cipher_to_plain

    def random_key(self) -> Dict[str, str]:
        """
        Generate a random substitution key.
        
        Creates a completely random mapping of ciphertext letters to plaintext
        letters. Useful for random restarts in optimization algorithms.
        
        Returns
        -------
        dict of {str: str}
            Dictionary mapping ciphertext letters (uppercase) to randomly
            shuffled plaintext letters (uppercase).
        """
        letters = list(self.alphabet)
        random.shuffle(letters)
        return dict(zip(self.alphabet, letters))
    
    def mutate_key(self, key: Dict[str, str], num_swaps: int = 1) -> Dict[str, str]:
        """
        Mutate a key by swapping random letter mappings.
        
        Randomly selects pairs of ciphertext letters and swaps their plaintext
        mappings. This creates a new key that is a small variation of the original.
        
        Parameters
        ----------
        key : dict of {str: str}
            The current substitution key to mutate.
        num_swaps : int, optional
            Number of random swaps to perform. Default is 1.
        
        Returns
        -------
        dict of {str: str}
            A new mutated key dictionary with swapped mappings.
        """
        mutated_key = key.copy()
        
        for _ in range(num_swaps):
            # Pick two random ciphertext letters to swap their plaintext mappings
            letters_to_swap = random.sample(list(mutated_key.keys()), 2)
            mutated_key[letters_to_swap[0]], mutated_key[letters_to_swap[1]] = \
                mutated_key[letters_to_swap[1]], mutated_key[letters_to_swap[0]]
        
        return mutated_key
    
    def swap_key_letters(self, key: Dict[str, str], letter1: str, letter2: str) -> Dict[str, str]:
        """
        Swap the plaintext mappings of two ciphertext letters in a key.
        
        Parameters
        ----------
        key : dict of {str: str}
            The current substitution key.
        letter1 : str
            First ciphertext letter (uppercase) to swap.
        letter2 : str
            Second ciphertext letter (uppercase) to swap.
        
        Returns
        -------
        dict of {str: str}
            A new key with swapped mappings.
        
        Raises
        ------
        ValueError
            If either letter1 or letter2 is not in the key.
        """
        if letter1 not in key or letter2 not in key:
            raise ValueError(f"Both letters must be in the key: {letter1}, {letter2}")
        
        mutated_key = key.copy()
        mutated_key[letter1], mutated_key[letter2] = mutated_key[letter2], mutated_key[letter1]
        return mutated_key
    
    def score_key(self, key: Dict[str, str], ciphertext: str):
        """
        Score a decryption key using n-gram language model.
        
        Decrypts the ciphertext with the given key and scores the resulting
        plaintext using the trained n-gram model. Higher scores indicate
        better decryption quality (more English-like text).
        
        Parameters
        ----------
        key : dict of {str: str}
            The substitution key to evaluate.
        ciphertext : str
            The encrypted text to decrypt and score.
        
        Returns
        -------
        float
            Score indicating the quality of the decryption. Higher scores
            indicate better decryption quality.
        """
        plaintext = self.decrypt_with_key(ciphertext, key)
        return self.ngram.score(plaintext)
    
    def _hill_climb(self, ciphertext: str, start_key: Dict[str, str], iters: int = 2000):
        """
        Perform hill climbing optimization to find the best decryption key.
        
        A greedy local search algorithm that always moves to better-scoring
        neighbors. Continues until no better neighbor is found or iteration
        limit is reached.
        
        Parameters
        ----------
        ciphertext : str
            The encrypted text to decrypt.
        start_key : dict of {str: str}
            Initial substitution key to start optimization from.
        iters : int, optional
            Maximum number of iterations to perform. Default is 2000.
        
        Returns
        -------
        best_key : dict of {str: str}
            The best key found during optimization.
        best_score : float
            The score of the best key found.
        """
        key = start_key
        score = self.score_key(key, ciphertext)
        best_key, best_score = key, score
        for step in range(iters):
            candidate = self.mutate_key(key, 1)
            cand_score = self.score_key(candidate, ciphertext)

            if cand_score > score:
                key, score = candidate, cand_score
                if cand_score > best_score:
                    best_key, best_score = candidate, cand_score
            # print(f"Step: {step}; cand_score: {cand_score}; best_score: {best_score}")
        
        return best_key, best_score
    
    def _temperature(self, step: int, max_steps: int, T_start, T_end):
        """
        Calculate temperature for simulated annealing at a given step.
        
        Uses exponential decay to decrease temperature from T_start to T_end
        over the course of optimization. This allows the algorithm to accept
        worse solutions early (exploration) and become more selective later
        (exploitation).
        
        Parameters
        ----------
        step : int
            Current iteration step.
        max_steps : int
            Total number of iterations.
        T_start : float
            Starting temperature (higher = more exploration).
        T_end : float
            Ending temperature (lower = more exploitation).
        
        Returns
        -------
        float
            Current temperature value.
        """
        # exponential decay (like epsilon decay)
        ratio = T_end / T_start
        return T_start * (ratio ** (step / max_steps))
    
    def _simulated_annealing(self, ciphertext: str, start_key: Dict[str, str], 
                             iters: int = 2000, T_start=3.0, T_end=1.0):
        """
        Perform simulated annealing optimization to find the best decryption key.
        
        A probabilistic optimization algorithm that can escape local optima by
        accepting worse solutions with a probability that decreases over time.
        Uses temperature to control the acceptance probability.
        
        Parameters
        ----------
        ciphertext : str
            The encrypted text to decrypt.
        start_key : dict of {str: str}
            Initial substitution key to start optimization from.
        iters : int, optional
            Maximum number of iterations to perform. Default is 2000.
        T_start : float, optional
            Starting temperature. Higher values allow more exploration.
            Default is 3.0.
        T_end : float, optional
            Ending temperature. Lower values allow more exploitation.
            Default is 1.0.
        
        Returns
        -------
        best_key : dict of {str: str}
            The best key found during optimization.
        best_score : float
            The score of the best key found.
        """
        key = start_key
        score = self.score_key(key, ciphertext)
        best_key, best_score = key, score

        for step in range(iters):
            T = self._temperature(step, iters, T_start, T_end)
            candidate = self.mutate_key(key)
            cand_score = self.score_key(candidate, ciphertext)
            delta = cand_score - score

            if delta > 0:
                key, score = candidate, cand_score
            else: 
                if random.random() < math.exp(delta / max(T, 1e-8)):
                    key, score = candidate, cand_score
            if score > best_score:
                best_key, best_score = key, score

            # print(f"Step: {step}; cand_score: {cand_score}; best_score: {best_score}")
        
        return best_key, best_score
    
    def temp_crack(self, ciphertext: str):
        """
        Crack ciphertext using frequency analysis and simulated annealing.
        
        A convenience method that generates an initial key from frequency
        analysis and then optimizes it using simulated annealing.
        
        Parameters
        ----------
        ciphertext : str
            The encrypted text to decrypt.
        
        Returns
        -------
        best_key : dict of {str: str}
            The best decryption key found.
        best_score : float
            The score of the best key.
        plaintext : str
            The decrypted text using the best key.
        """
        initial_key = self.frequency_initial_key(ciphertext)
        best_key, best_score= self._simulated_annealing(ciphertext, initial_key, 2000)
        plaintext = self.decrypt_with_key(ciphertext, best_key)
        return best_key, best_score, plaintext
            
    
    def crack(self, ciphertext: str, method: str = "anneal", restarts: int = 20) -> dict:
        """
        Crack substitution cipher using optimization with multiple restarts.
        
        Main method for breaking substitution ciphers. Starts with a frequency-based
        initial key, then performs multiple optimization runs with random restarts
        to avoid local optima. Returns the best solution found across all runs.
        
        Parameters
        ----------
        ciphertext : str
            The encrypted text to decrypt.
        method : str, optional
            Optimization method to use. Options are:
            - "anneal" : Simulated annealing (default)
            - "hill" : Hill climbing
            Default is "anneal".
        restarts : int, optional
            Number of optimization runs to perform (including the initial
            frequency-based run). Default is 20.
        
        Returns
        -------
        dict
            Dictionary containing:
            - "best_key" : dict of {str: str}
                The best decryption key found.
            - "best_score" : float
                The score of the best key.
            - "best_plaintext" : str
                The decrypted text using the best key.
        
        Raises
        ------
        ValueError
            If method is not "anneal" or "hill".
        """
        freq_initial_key = self.frequency_initial_key(ciphertext)

        best_overall_key = None
        best_overall_score = float("-inf")

        if method == "hill":
            key, score = self._hill_climb(ciphertext, freq_initial_key)
        elif method == "anneal":
            key, score = self._simulated_annealing(ciphertext, freq_initial_key)
        else:
            raise ValueError(f"Invalid argument for method: {method}")

        best_overall_key, best_overall_score = key, score
        for _ in range(restarts-1):
            start_key = self.random_key()
            if method == "hill":
                key, score = self._hill_climb(ciphertext, start_key)
            else:
                key, score = self._simulated_annealing(ciphertext, start_key)
            
            if score > best_overall_score:
                best_overall_key, best_overall_score = key, score
        
        best_plaintext = self.decrypt_with_key(ciphertext, best_overall_key)

        return {
            "best_key": best_overall_key,
            "best_score": best_overall_score,
            "best_plaintext": best_plaintext
        }
    
    
if __name__ == '__main__':
    d = Decrypter()
    with open('input_text.txt', 'r') as f:
        text = f.read()
    cc = CaesarCipher(1)
    ciphertext_cc = cc.encrypt(text) 
    results = d.crack(ciphertext_cc)
    print(results)
    

        