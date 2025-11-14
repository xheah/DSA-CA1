try:
    from Ciphers.cipher import Cipher
except ModuleNotFoundError:
    from cipher import Cipher

class PlayfairCipher(Cipher):
    def __init__(self, key: str):
        super().__init__()
        self.__key = ''.join(filter(str.isalpha, key)).upper()
        self.__key = self.__key.replace('J', 'I')
        self._alphabet = self._alphabet.replace('J', '')
        self.__key = self._generate_key()
        self.__playfair_square = self.create_playfair_square()

    def _generate_key(self):
        seen = set()
        output = []
        for ch in self.__key + self._alphabet:
            if ch not in seen:
                seen.add(ch)
                output.append(ch)
        return ''.join(output)

    def create_playfair_square(self):
        n_cols = 5
        grid = [[j for j in self.__key[i:i+n_cols]] for i in range(0, 25, n_cols)]
        return grid

    def find_location(self, char):
        """Helper function to get row and column of given char"""
        for i in range(0, 5):
            for j in range(0, 5):
                if self.__playfair_square[i][j] == char:
                    return i, j
        return None
    
    def clean_text(self, text: str):
        """Prepare text for Playfair encryption by handling duplicates and padding"""
        i = 0 
        while i < len(text) - 1:
            if text[i] == text[i+1]:
                filler = 'Q' if text[i] == 'X' else 'X'
                text = text[:i+1] + filler + text[i+1:]
                i += 2  # Skip past the original letter and the filler
            else: 
                i += 1
        if len(text) % 2 == 1:
            text += 'X'
        return text
    
    def encrypt_digraphs(self, letters):
        ciphertext = []
        for i in range(0, len(letters), 2):
            digraph = letters[i:i+2]
            r1, c1 = self.find_location(digraph[0])
            r2, c2, = self.find_location(digraph[1])
            if r1 == r2:
                sub1 = self.__playfair_square[r1][(c1 + 1) % 5]
                sub2 = self.__playfair_square[r2][(c2 + 1) % 5]
            elif c1 == c2: 
                sub1 = self.__playfair_square[(r1 + 1) % 5][c1]
                sub2 = self.__playfair_square[(r2 + 1) % 5][c2]
            else:
                sub1 = self.__playfair_square[r1][c2]
                sub2 = self.__playfair_square[r2][c1]
            ciphertext.append(sub1)
            ciphertext.append(sub2)
        return ciphertext


    def get_key(self):
        return self.__key

    def get_square(self):
        return self.__playfair_square

    def encrypt(self, text: str):
        """Encrypt text using Playfair cipher"""
        # Extract letters and track non-letters with their positions
        letters_only = []
        non_letter_positions = {}  # position in original text -> char
        
        for i, char in enumerate(text):
            if char.isalpha():
                # Replace J with I for Playfair
                letters_only.append('I' if char.upper() == 'J' else char.upper())
            else:
                non_letter_positions[i] = char
        
        # Clean text (add filler for double letters, pad if odd length)
        cleaned = self.clean_text(''.join(letters_only))
        
        # Encrypt the digraphs
        encrypted_letters = self.encrypt_digraphs(list(cleaned))
        
        # Reconstruct output preserving non-letters and case
        output = []
        letter_idx = 0
        original_idx = 0
        
        for char in text:
            if char.isalpha():
                # Get encrypted letter and preserve original case
                encrypted_char = encrypted_letters[letter_idx]
                if char.islower():
                    output.append(encrypted_char.lower())
                else:
                    output.append(encrypted_char)
                letter_idx += 1
            else:
                output.append(char)
        
        return ''.join(output)
    
    def decrypt_digraphs(self, letters):
        """Decrypt digraphs using Playfair rules"""
        plaintext = []
        for i in range(0, len(letters), 2):
            digraph = letters[i:i+2]
            r1, c1 = self.find_location(digraph[0])
            r2, c2 = self.find_location(digraph[1])
            
            if r1 == r2:
                # Same row: shift left (wrap around)
                sub1 = self.__playfair_square[r1][(c1 - 1) % 5]
                sub2 = self.__playfair_square[r2][(c2 - 1) % 5]
            elif c1 == c2:
                # Same column: shift up (wrap around)
                sub1 = self.__playfair_square[(r1 - 1) % 5][c1]
                sub2 = self.__playfair_square[(r2 - 1) % 5][c2]
            else:
                # Different row and column: swap columns
                sub1 = self.__playfair_square[r1][c2]
                sub2 = self.__playfair_square[r2][c1]
            
            plaintext.append(sub1)
            plaintext.append(sub2)
        return plaintext
    
    def remove_filler(self, text: str):
        """Remove filler X/Q characters added during encryption"""
        if not text:
            return text
        
        result = []
        i = 0
        while i < len(text):
            # Fillers are inserted between duplicate letters: "LL" -> "LXL"
            # So we look for pattern: letter-X/Q-letter (same letter on both sides)
            if i < len(text) - 2 and text[i] == text[i+2] and text[i+1] in ['X', 'Q']:
                # Found filler pattern: letter-X/Q-letter, collapse to duplicate letter
                result.append(text[i])
                result.append(text[i])  # Add the duplicate
                i += 3  # Skip letter, filler, and second letter
            elif i == len(text) - 1 and text[i] == 'X':
                # Trailing X padding (from odd-length text), skip it
                break
            else:
                result.append(text[i])
                i += 1
        
        return ''.join(result)

    def decrypt(self, text: str):
        """Decrypt text using Playfair cipher"""
        # Extract letters and track non-letters with their positions
        letters_only = []
        letter_positions = []  # Track which positions in text are letters
        
        for i, char in enumerate(text):
            if char.isalpha():
                # Replace J with I for Playfair
                letters_only.append('I' if char.upper() == 'J' else char.upper())
                letter_positions.append(i)
        
        if not letters_only:
            return text  # No letters to decrypt
        
        # Decrypt the digraphs
        decrypted_letters = self.decrypt_digraphs(letters_only)
        decrypted_text = ''.join(decrypted_letters)
        
        # Remove filler characters
        decrypted_text = self.remove_filler(decrypted_text)
        
        # Reconstruct output preserving non-letters and case
        output = list(text)  # Start with original text
        decrypted_idx = 0
        
        # Replace letters in their original positions
        for pos in letter_positions:
            if decrypted_idx < len(decrypted_text):
                decrypted_char = decrypted_text[decrypted_idx]
                # Preserve original case
                if output[pos].islower():
                    output[pos] = decrypted_char.lower()
                else:
                    output[pos] = decrypted_char
                decrypted_idx += 1
        
        return ''.join(output)
if __name__ == '__main__':
    pc = PlayfairCipher('SECRETKEY')
    print(pc.get_key())
    print(pc._alphabet)
    print(pc.get_square())
    print(pc.encrypt('THE HACKING BLOG ROCKS'))