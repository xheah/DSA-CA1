from Ciphers.cipher import Cipher

class KeywordCipher(Cipher):
    def __init__(self, keyword: str):
        super().__init__()
        keyword = ''.join([kw for kw in keyword if kw.isalpha()])
        if not keyword:
            raise ValueError("Keyword must contain at least 1 alphabetic character")
        self._keyword = keyword.upper()
        self.__keyword_cipher = self._generate_keyword_cipher()
        # Set up the translation dictionaries using base class method
        self._set_cipher_alphabet(self.__keyword_cipher)

    def _generate_keyword_cipher(self):
        seen = set()
        result = []
        for ch in self._keyword + self._alphabet:
            if ch not in seen:
                seen.add(ch)
                result.append(ch)
        return ''.join(result)
    
    def encrypt(self, original: str):
        encrypted = []
        for ch in original:
            if not ch.isalpha():
                encrypted.append(ch)
                continue
            if ch.isupper():
                encrypted.append(self._alphabet_to_cipher[ch])
            else:
                encrypted.append(self._alphabet_to_cipher[ch.upper()].lower())
        return ''.join(encrypted)

    def decrypt(self, encrypted: str):
        translated = []
        for ch in encrypted:
            if not ch.isalpha():
                translated.append(ch)
                continue
            if ch.isupper():
                translated.append(self._cipher_to_alphabet[ch])
            else:
                translated.append(self._cipher_to_alphabet[ch.upper()].lower())
        return ''.join(translated)
    
    def get_keyword_cipher(self):
        return self.__keyword_cipher
    
    def get_keyword(self):
        return self._keyword
    
    def __str__(self):
        return f'KeywordCipher with keyword: {self._keyword}'
    
    