from Ciphers.cipher import Cipher


class VigenereCipher(Cipher):
    """
    Vigenere Cipher implementation.
    
    A polyalphabetic substitution cipher that uses a keyword to determine
    which Caesar shift to apply to each letter. The key is repeated to
    match the length of the plaintext.
    
    Attributes
    ----------
    key : str
        The keyword used for encryption (uppercase, alphabetic only).
    key_num : list of int
        List of numeric indices (0-25) corresponding to each letter in key.
    """
    
    def __init__(self, key: str):
        """
        Initialize VigenereCipher with a keyword.
        
        Parameters
        ----------
        key : str
            Keyword to use for encryption. Non-alphabetic characters are
            filtered out. Must contain at least one letter.
        
        Raises
        ------
        ValueError
            If key contains no alphabetic characters after filtering.
        
        Notes
        -----
        The key is converted to uppercase and non-alphabetic characters
        are removed. The key is repeated cyclically during encryption/decryption.
        """
        super().__init__()
        self.key = ''.join(ch.upper() for ch in key if ch.isalpha())
        self.key_num = [self._alphabet_index[ch] for ch in self.key]
        if not self.key_num:
            raise ValueError('Key must contain at least one alphabetic character.')
    
    def encrypt(self, text: str):
        """
        Encrypt text using Vigenere cipher.
        
        Each letter is encrypted using a Caesar shift determined by the
        corresponding letter in the key (repeated cyclically). Non-alphabetic
        characters are preserved and don't advance the key position.
        
        Parameters
        ----------
        text : str
            Plaintext to encrypt.
        
        Returns
        -------
        str
            Encrypted ciphertext with case and non-alphabetic characters
            preserved.
        
        Notes
        -----
        Encryption formula: C_i = (P_i + K_i) mod 26
        where P_i is plaintext letter index, K_i is key letter index.
        The key index cycles through the key length.
        """
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
        """
        Decrypt text using Vigenere cipher.
        
        Each letter is decrypted using a Caesar shift determined by the
        corresponding letter in the key (repeated cyclically). Non-alphabetic
        characters are preserved and don't advance the key position.
        
        Parameters
        ----------
        text : str
            Ciphertext to decrypt.
        
        Returns
        -------
        str
            Decrypted plaintext with case and non-alphabetic characters
            preserved.
        
        Notes
        -----
        Decryption formula: P_i = (C_i - K_i) mod 26
        where C_i is ciphertext letter index, K_i is key letter index.
        The key index cycles through the key length.
        """
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
    
    def __str__(self):
        """
        Return string representation of the cipher.
        
        Returns
        -------
        str
            String in format "Vigenere Cipher with key: [KEY]".
        """
        return f"Vigenere Cipher with key: {self.key}"