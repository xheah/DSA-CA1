from Ciphers.cipher import Cipher
from math import gcd


class AffineCipher(Cipher):
    """
    Affine Cipher implementation.
    
    A substitution cipher that uses a mathematical function to encrypt letters.
    Each letter is encrypted using the formula: E(x) = (ax + b) mod 26,
    where 'a' and 'b' are the key values.
    
    Attributes
    ----------
    a : int
        First key value. Must be coprime with 26 (alphabet length).
    b : int
        Second key value. Can be any integer (modulo 26).
    """
    
    def __init__(self, key: list[int]):
        """
        Initialize AffineCipher with key values.
        
        Parameters
        ----------
        key : list of int
            Two-element list [a, b] where:
            - a: Must be coprime with 26 (gcd(a, 26) = 1)
            - b: Can be any integer
        
        Raises
        ------
        ValueError
            If 'a' is not coprime with 26 (alphabet length).
        
        Notes
        -----
        The value 'a' must be coprime with 26 for the cipher to be invertible.
        Valid values for 'a' include: 1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25.
        """
        super().__init__()
        self.a = key[0]
        if gcd(self.a, len(self._alphabet)) > 1:
            raise ValueError(f'a and the length of the alphabet ({len(self._alphabet)}) must be coprime')
        self.b = key[1]

    def __encryption_formula(self, ch: str):
        """
        Apply affine encryption formula to a single character.
        
        Parameters
        ----------
        ch : str
            Single uppercase letter to encrypt.
        
        Returns
        -------
        str
            Encrypted letter (uppercase).
        
        Notes
        -----
        Formula: E(x) = (a * index(x) + b) mod 26
        """
        num = (self.a * self._alphabet_index[ch] + self.b) % len(self._alphabet)
        return self._index_to_alphabet[num]
    
    def __decryption_formula(self, ch: str):
        """
        Apply affine decryption formula to a single character.
        
        Parameters
        ----------
        ch : str
            Single uppercase letter to decrypt.
        
        Returns
        -------
        str
            Decrypted letter (uppercase).
        
        Notes
        -----
        Formula: D(x) = a^(-1) * (index(x) - b) mod 26
        where a^(-1) is the modular multiplicative inverse of a mod 26.
        """
        num = (
            pow(self.a, -1, len(self._alphabet))
            * (self._alphabet_index[ch] - self.b)
        ) % len(self._alphabet)
        return self._index_to_alphabet[num]

    def encrypt(self, text: str):
        """
        Encrypt text using affine cipher.
        
        Parameters
        ----------
        text : str
            Plaintext to encrypt.
        
        Returns
        -------
        str
            Encrypted ciphertext with case and non-alphabetic characters
            preserved.
        """
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
        """
        Decrypt text using affine cipher.
        
        Parameters
        ----------
        text : str
            Ciphertext to decrypt.
        
        Returns
        -------
        str
            Decrypted plaintext with case and non-alphabetic characters
            preserved.
        """
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
        """
        Return string representation of the cipher.
        
        Returns
        -------
        str
            String in format "Cipher: AffineCipher".
        """
        return super().__str__()