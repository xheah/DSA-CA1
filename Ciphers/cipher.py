class Cipher:
    def __init__(self):
        self._alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        self._alphabet_to_cipher = {}
        self._cipher_to_alphabet = {}
        self._alphabet_index = {ch: idx for idx, ch in enumerate(self._alphabet)}
        self._index_to_alphabet = {idx: ch for idx, ch in enumerate(self._alphabet)}

    def _set_cipher_alphabet(self, cipher_alphabet: str):
        """Set up the translation dictionaries given a cipher alphabet"""
        if len(cipher_alphabet) != len(self._alphabet):
            raise ValueError("Cipher alphabet must be same length as standard alphabet")
        self._alphabet_to_cipher = dict(zip(self._alphabet, cipher_alphabet))
        self._cipher_to_alphabet = dict(zip(cipher_alphabet, self._alphabet))
    
    def encrypt(self, text: str):
        """Encrypt text using the cipher"""
        raise NotImplementedError('Encrypt must be implemented in a subclass')

    def decrypt(self, text: str):
        """Decrypt text using the cipher"""
        raise NotImplementedError('Decrypt must be implemented in a subclass')

    def __str__(self):
        return f'Cipher: {self.__class__.__name__}'
    
