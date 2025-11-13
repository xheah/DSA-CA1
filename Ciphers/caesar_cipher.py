from Ciphers.cipher import Cipher

class CaesarCipher(Cipher):
    def __init__(self, shift: int):
        super().__init__()
        self.__shift = int(shift) % len(self._alphabet)
        cipher_alphabet = self._create_cipher_alphabet()
        # Set up the translation dictionaries using base class method
        self._set_cipher_alphabet(cipher_alphabet)

    def _create_cipher_alphabet(self):
        """Create shifted alphabet"""
        return self._alphabet[-self.__shift:] + self._alphabet[:-self.__shift]
    
    def encrypt(self, text: str):
        output = []
        for ch in text:
            if ch.isalpha():
                if ch.islower():
                    output.append(self._alphabet_to_cipher[ch.upper()].lower())
                else:
                    output.append(self._alphabet_to_cipher[ch])
            else: 
                output.append(ch)
        return ''.join(output)
    
    def decrypt(self, text: str):
        output = []
        for ch in text:
            if ch.isalpha():
                if ch.islower():
                    output.append(self._cipher_to_alphabet[ch.upper()].lower())
                else:
                    output.append(self._cipher_to_alphabet[ch])
            else:
                output.append(ch)
        return ''.join(output)

    def __str__(self):
        return f'CaesarCipher with shift: {self.__shift}'
    
    def get_shift(self):
        return self.__shift
