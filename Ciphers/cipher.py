class Cipher:
    """
    Base class for cryptographic ciphers.
    
    Provides common infrastructure for cipher implementations including
    alphabet management and translation dictionaries. Subclasses must
    implement encrypt and decrypt methods.
    
    Attributes
    ----------
    _alphabet : str
        Standard alphabet string (A-Z).
    _alphabet_to_cipher : dict of {str: str}
        Dictionary mapping standard alphabet letters to cipher alphabet.
    _cipher_to_alphabet : dict of {str: str}
        Dictionary mapping cipher alphabet letters to standard alphabet.
    _alphabet_index : dict of {str: int}
        Dictionary mapping letters to their index positions (0-25).
    _index_to_alphabet : dict of {int: str}
        Dictionary mapping indices to letters.
    """
    
    def __init__(self):
        """
        Initialize base Cipher class.
        
        Sets up the standard alphabet and initializes empty translation
        dictionaries. Subclasses should call this and then set up their
        specific cipher alphabet mappings.
        """
        self._alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        self._alphabet_to_cipher = {}
        self._cipher_to_alphabet = {}
        self._alphabet_index = {ch: idx for idx, ch in enumerate(self._alphabet)}
        self._index_to_alphabet = {idx: ch for idx, ch in enumerate(self._alphabet)}

    def _set_cipher_alphabet(self, cipher_alphabet: str):
        """
        Set up translation dictionaries given a cipher alphabet.
        
        Creates bidirectional mappings between the standard alphabet and
        the cipher alphabet for efficient encryption/decryption operations.
        
        Parameters
        ----------
        cipher_alphabet : str
            Cipher alphabet string. Must be exactly 26 characters long
            and contain each letter exactly once.
        
        Raises
        ------
        ValueError
            If cipher_alphabet length does not match standard alphabet length.
        
        Notes
        -----
        This method sets up both forward (alphabet -> cipher) and reverse
        (cipher -> alphabet) mappings for efficient lookups.
        """
        if len(cipher_alphabet) != len(self._alphabet):
            raise ValueError("Cipher alphabet must be same length as standard alphabet")
        self._alphabet_to_cipher = dict(zip(self._alphabet, cipher_alphabet))
        self._cipher_to_alphabet = dict(zip(cipher_alphabet, self._alphabet))

    def _transform_text(self, text: str, transform_func) -> str:
        """
        Apply transformation function to text while preserving case and non-alphabetic chars.
        
        Parameters
        ----------
        text : str
            Text to transform.
        transform_func : callable
            Function that takes uppercase letter and returns transformed uppercase letter.
        
        Returns
        -------
        str
            Transformed text with case preserved.
        """
        result = []
        for ch in text:
            if not ch.isalpha():
                result.append(ch)
            else:
                transformed = transform_func(ch.upper())
                result.append(transformed if ch.isupper() else transformed.lower())
        return ''.join(result)
    
    def encrypt(self, text: str):
        """
        Encrypt text using the cipher.
        
        Parameters
        ----------
        text : str
            Plaintext to encrypt.
        
        Returns
        -------
        str
            Encrypted ciphertext.
        
        Raises
        ------
        NotImplementedError
            This method must be implemented in a subclass.
        """
        raise NotImplementedError('Encrypt must be implemented in a subclass')

    def decrypt(self, text: str):
        """
        Decrypt text using the cipher.
        
        Parameters
        ----------
        text : str
            Ciphertext to decrypt.
        
        Returns
        -------
        str
            Decrypted plaintext.
        
        Raises
        ------
        NotImplementedError
            This method must be implemented in a subclass.
        """
        raise NotImplementedError('Decrypt must be implemented in a subclass')

    def __str__(self):
        """
        Return string representation of the cipher.
        
        Returns
        -------
        str
            String in format "Cipher: [ClassName]".
        """
        return f'Cipher: {self.__class__.__name__}'
    
