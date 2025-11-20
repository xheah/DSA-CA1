from Ciphers.cipher import Cipher


class CaesarCipher(Cipher):
    """
    Caesar Cipher implementation.
    
    A substitution cipher that shifts each letter by a fixed number of
    positions in the alphabet. Also known as a shift cipher or ROT cipher.
    
    Attributes
    ----------
    __shift : int
        The shift value (0-25), automatically wrapped to valid range.
    """
    
    def __init__(self, shift: int):
        """
        Initialize CaesarCipher with a shift value.
        
        Parameters
        ----------
        shift : int
            Number of positions to shift the alphabet. Automatically
            wrapped modulo 26 to ensure valid range (0-25).
        
        Notes
        -----
        Negative shifts and shifts greater than 25 are automatically
        converted to the equivalent value in the 0-25 range using modulo.
        """
        super().__init__()
        self.__shift = int(shift) % len(self._alphabet)
        cipher_alphabet = self._create_cipher_alphabet()
        # Set up the translation dictionaries using base class method
        self._set_cipher_alphabet(cipher_alphabet)

    def _create_cipher_alphabet(self):
        """
        Create shifted alphabet for Caesar cipher.
        
        Generates the cipher alphabet by rotating the standard alphabet
        by the shift amount. Letters at the end wrap around to the beginning.
        
        Returns
        -------
        str
            26-character string representing the shifted alphabet.
        
        Examples
        --------
        For shift=3: "XYZABCDEFGHIJKLMNOPQRSTUVW"
        """
        return self._alphabet[-self.__shift:] + self._alphabet[:-self.__shift]
    
    def encrypt(self, text: str):
        """
        Encrypt text using Caesar cipher.
        
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
        return self._transform_text(text, lambda ch: self._alphabet_to_cipher[ch])
    
    def decrypt(self, text: str):
        """
        Decrypt text using Caesar cipher.
        
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
        return self._transform_text(text, lambda ch: self._cipher_to_alphabet[ch])

    def __str__(self):
        """
        Return string representation of the cipher.
        
        Returns
        -------
        str
            String in format "CaesarCipher with shift: [SHIFT]".
        """
        return f'CaesarCipher with shift: {self.__shift}'
    
    def get_shift(self):
        """
        Get the shift value used for this cipher.
        
        Returns
        -------
        int
            The shift value (0-25).
        """
        return self.__shift
