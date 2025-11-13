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
        i = 0 
        while i < len(text) - 1:
            if text[i] == text[i+1]:
                filler = 'Q' if text[i] == 'X' else 'X'
                text = text[:i+1] + filler + text[i+1:]
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
        letters = []
        nonletters = {}
        for i, char in enumerate(text):
            if not char.isalpha():
                nonletters[i] = char
            else:
                letters.append('I' if char == 'J' else char)
        letters = list(self.clean_text(''.join(letters)))
        ciphertext = self.encrypt_digraphs(letters)
        return ciphertext
        

    def decrypt(self, text: str):
        pass
if __name__ == '__main__':
    pc = PlayfairCipher('SECRETKEY')
    print(pc.get_key())
    print(pc._alphabet)
    print(pc.get_square())
    print(pc.encrypt('THEHACKINGBLOGROCKS'))