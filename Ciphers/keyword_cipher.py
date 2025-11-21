from Ciphers.cipher import Cipher


class KeywordCipher(Cipher):
    """
    Keyword Cipher implementation.
    
    A substitution cipher that uses a keyword to generate a mixed alphabet.
    The keyword letters appear first in the cipher alphabet, followed by
    the remaining letters in order, with duplicates removed.
    
    Attributes
    ----------
    __keyword : str
        The keyword used to generate the cipher alphabet (uppercase).
    __keyword_cipher : str
        The generated cipher alphabet (26 unique letters).
    """
    
    def __init__(self, keyword: str):
        """
        Initialize KeywordCipher with a keyword.
        
        Parameters
        ----------
        keyword : str
            Keyword to use for generating the cipher alphabet. Non-alphabetic
            characters are filtered out. Must contain at least one letter.
        
        Raises
        ------
        ValueError
            If keyword contains no alphabetic characters after filtering.
        
        Notes
        -----
        The keyword is converted to uppercase and non-alphabetic characters
        are removed. Duplicate letters in the keyword are handled when
        generating the cipher alphabet.
        """
        super().__init__()
        keyword = ''.join([kw for kw in keyword if kw.isalpha()])
        if not keyword:
            raise ValueError("Keyword must contain at least 1 alphabetic character")
        self.__keyword = keyword.upper()
        self.__keyword_cipher = self.__generate_keyword_cipher()
        # Set up the translation dictionaries using base class method
        self._set_cipher_alphabet(self.__keyword_cipher)

    def __generate_keyword_cipher(self):
        """
        Generate cipher alphabet from keyword.
        
        Creates a 26-letter alphabet by placing keyword letters first
        (removing duplicates), followed by remaining alphabet letters
        in order.
        
        Returns
        -------
        str
            26-character string representing the cipher alphabet.
        """
        seen = set()
        result = []
        for ch in self.__keyword + self._alphabet:
            if ch not in seen:
                seen.add(ch)
                result.append(ch)
        return ''.join(result)
    
    def encrypt(self, text: str):
        """
        Encrypt text using keyword cipher.
        
        Parameters
        ----------
        original : str
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
        Decrypt text using keyword cipher.
        
        Parameters
        ----------
        encrypted : str
            Ciphertext to decrypt.
        
        Returns
        -------
        str
            Decrypted plaintext with case and non-alphabetic characters
            preserved.
        """
        return self._transform_text(text, lambda ch: self._cipher_to_alphabet[ch])
    
    def get_keyword_cipher(self):
        """
        Get the generated cipher alphabet.
        
        Returns
        -------
        str
            The 26-character cipher alphabet string.
        """
        return self.__keyword_cipher
    
    def get_keyword(self):
        """
        Get the keyword used for this cipher.
        
        Returns
        -------
        str
            The keyword (uppercase, filtered to alphabetic characters only).
        """
        return self.__keyword
    
    def __str__(self):
        """
        Return string representation of the cipher.
        
        Returns
        -------
        str
            String in format "KeywordCipher with keyword: [KEYWORD]".
        """
        return f'KeywordCipher with keyword: {self.__keyword}'
    
    