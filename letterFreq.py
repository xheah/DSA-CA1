import string
from math import ceil
from Ciphers.keyword_cipher import KeywordCipher
class LFD: # letter frequency distribution
    def __init__(self, text: str):
        self.__text = text
        self.__alphabet = string.ascii_uppercase 
        self.__fd = self.count_frequency() # Frequency Distribution
        self.__fdp = self.calculate_percentages() # Frequency Distribution Percentages
        self.__top5 = self.calc_top5()
        self.__english_frequencies = {
            'A': 8.2, 'B': 1.5, 'C': 2.8, 'D': 4.3, 'E': 12.7, 'F': 2.2,
            'G': 2.0, 'H': 6.1, 'I': 7.0, 'J': 0.15, 'K': 0.77, 'L': 4.0,
            'M': 2.4, 'N': 6.7, 'O': 7.5, 'P': 1.9, 'Q': 0.095, 'R': 6.0,
            'S': 6.3, 'T': 9.1, 'U': 2.8, 'V': 0.98, 'W': 2.4, 'X': 0.15,
            'Y': 2.0, 'Z': 0.074
        }

    # get the number of times each letter appears
    def count_frequency(self) -> dict:
        """Count the frequency of each letter"""
        fd = {chr(i): 0 for i in range(ord('A'), ord('Z') + 1)}
        for ch in self.__text:
            if ch.isalpha():
                fd[ch.upper()] += 1
        return fd
    
    # calculate the frequency percentages
    def calculate_percentages(self) -> dict:
        """Calculate the frequency percentage of each letter"""
        total_letters = sum(self.__fd.values())
        if total_letters == 0:
            return {alpha: 0.0 for alpha in self.__fd.keys()}
        return {alpha: round(perc / total_letters * 100, 2) for alpha, perc in self.__fd.items()}

    # get the top 5 most frequent letters
    def calc_top5(self) -> list[tuple]:
        """Return the top 5 most frequent letters"""
        sorted_freqs = sorted(self.__fdp.items(), key=lambda x: (-x[1], x[0]))
        return sorted_freqs[:5]

    
    def infer_keyword(self, keywords: list):
        """Infer the keyword from a given text and a list of keyword candidates"""
        try:
            with open('dictionary.txt', 'r') as f:
                dictionary = set(word.strip() for word in f.read().split('\n') if word.strip())
        except FileNotFoundError:
            print("Error: dictionary.txt does not exist")
            return ''
        scores = {}
        for keyword in keywords:
            if not keyword.strip():
                continue
            kwc = KeywordCipher(keyword.strip().upper())
            decrypted = kwc.decrypt(self.__text)
            alpha_decrypted = ''.join(ch for ch in decrypted if ch.isalpha() or ch.isspace())
            words_decrypted = [w for w in alpha_decrypted.split(' ') if w]
            total_words = len(words_decrypted)
            if total_words == 0:
                continue
            score = sum(1 for w in words_decrypted if w in dictionary)
            scores[keyword] = round(score / total_words, 2)
        if not scores:
            return ''
        best: str = sorted(scores.items(), key = lambda x: x[1], reverse=True)[0]
        if best[1] < 0.10:
            return 'no keyword found'
        return best[0]

    # GETTERS
    def get_fd(self) -> dict:
        return self.__fd
    
    def get_fdp(self) -> dict:
        return self.__fdp

    def get_top5(self) -> list[tuple]:
        return self.__top5
    
    def get_eng_freq(self) -> dict:
        return self.__english_frequencies
    
    # SETTERS

    def set_fd(self, val: dict):
        self.__fd = val

    def set_fdp(self, val: dict):
        self.__fdp = val

    def set_top5(self, val:list[tuple]):
        self.__top5 = val
    
    def set_eng_freq(self, val: dict):
        self.__english_frequencies = val

    def __str__(self):
        top5 = self.get_top5()
        percentages = self.get_fdp()
        letters = list(self.__alphabet)
        height = len(letters)
        
        # Calculate bar heights (scaled to height)
        unit = 100 / height
        alpha_h = {alpha: ceil(p / unit) for alpha, p in percentages.items()}
        
        # Build output lines efficiently using list
        output_lines = []
        
        # Build graph rows (top to bottom)
        for y_lvl in range(height, 0, -1):
            # Build graph row using list comprehension
            graph_chars = [
                '*' if alpha_h.get(letter, 0) >= y_lvl else ' '
                for letter in letters
            ]
            graph_row = '  '.join(graph_chars)
            
            # Get current letter info
            current_letter = letters[height - y_lvl]
            letter_info = f'| {current_letter}- {percentages[current_letter]:.2f}%'
            
            # Build right panel (TOP 5 section)
            right_panel = ''
            top = 16
            if y_lvl == top:  # First row - title
                right_panel = '\t\tTOP 5 FREQ'
            elif y_lvl == top - 1:  # Second row - separator
                right_panel = '\t\t' + '-' * 10
            elif y_lvl >= top - 6:  # Next 5 rows - top 5 entries
                top5_idx = top - y_lvl - 2
                if 0 <= top5_idx < len(top5):
                    letter, pct = top5[top5_idx]
                    right_panel = f'\t\t| {letter}- {pct:.2f}%'
            
            output_lines.append(graph_row + letter_info + right_panel)
        
        # Add separator line
        alphabet_line = '  '.join(letters)
        output_lines.append('_' * len(alphabet_line) + '|')
        
        # Add bottom alphabet labels
        output_lines.append(alphabet_line)
        
        return '\n'.join(output_lines)
        