from Ciphers.cipher import Cipher
class VigenereCipher(Cipher):
    def __init__(self, key: str):
        super().__init__()
        self.key = ''.join(ch.upper() for ch in key if ch.isalpha())
        self.key_num = [self._alphabet_index[ch] for ch in self.key]
        if not self.key_num:
            raise ValueError('Key must contain at least one alphabetic character.')
    
    def encrypt(self, text: str):
        encrypted = []
        m = len(self._alphabet)
        ki = 0 # index of current key_num
        for ch in text:
            if not ch.isalpha():
                encrypted.append(ch)
                continue
            is_upper = ch.isupper()
            base = ch.upper()
            if base not in self._alphabet:
                encrypted.append(ch)
                continue
            p = self._alphabet_index[base]
            k = self.key_num[ki % len(self.key_num)]
            c = self._index_to_alphabet[(p + k) % m]
            encrypted.append(c if is_upper else c.lower())
            ki += 1
        return ''.join(encrypted)
    
    def decrypt(self, text: str):
        decrypted = []
        m = len(self._alphabet)
        ki = 0
        for ch in text:
            if not ch.isalpha():
                decrypted.append(ch)
                continue
            base = ch.upper()
            if base not in self._alphabet:
                decrypted.append(ch)
                continue
            c = self._alphabet_index[base]
            k = self.key_num[ki % len(self.key_num)]
            p = self._index_to_alphabet[(c - k) % m]
            decrypted.append(p if ch.isupper() else p.lower())
            ki += 1
        return ''.join(decrypted)