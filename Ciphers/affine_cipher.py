from Ciphers.cipher import Cipher
from math import gcd

class AffineCipher(Cipher):
    def __init__(self, key: list[int]):
        super().__init__()
        self.a = key[0]
        if gcd(self.a, len(self._alphabet)) > 1:
            raise ValueError(f'a and the length of the alphabet ({len(self._alphabet)}) must be coprime')
        self.b = key[1]

    def __encryption_formula(self, ch: str):
        num = (self.a * self._alphabet_index[ch] + self.b) % len(self._alphabet)
        return self._index_to_alphabet[num]
    
    def __decryption_formula(self, ch: str):
        num = (
            pow(self.a, -1, len(self._alphabet))
            * (self._alphabet_index[ch] - self.b)
        ) % len(self._alphabet)
        return self._index_to_alphabet[num]

    def encrypt(self, text: str):
        encrypted = []
        for ch in text:
            if not ch.isalpha():
                encrypted.append(ch)
                continue
            if ch.isupper():
                encrypted.append(self.__encryption_formula(ch))
            else:
                encrypted.append(self.__encryption_formula(ch.upper()).lower())
        return ''.join(encrypted)

    def decrypt(self, text:str):
        decrypted = [] 
        for ch in text:
            if not ch.isalpha():
                decrypted.append(ch)
                continue
            if ch.isupper():
                decrypted.append(self.__decryption_formula(ch))
            else:
                decrypted.append(self.__decryption_formula(ch.upper()).lower())
        return ''.join(decrypted)

    def __str__(self):
        return super().__str__()