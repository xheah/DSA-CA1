from math import log


class NGramModel:
    """
    N-gram language model for text scoring using add-k smoothing.
    
    This class implements an n-gram language model that can be trained on
    a corpus and used to score text based on the probability of n-gram
    sequences. Uses add-k (Laplace) smoothing to handle unseen n-grams.
    
    Attributes
    ----------
    n : int
        The size of n-grams (default is 3 for trigrams).
    k : float
        Smoothing parameter for add-k smoothing (default is 0.1).
    counts : dict of {str: int}
        Dictionary mapping n-grams to their counts in the training corpus.
    total : int
        Total number of n-grams in the training corpus.
    log_probs : dict of {str: float}
        Dictionary mapping n-grams to their log probabilities.
    floor : float or None
        Log probability for unseen n-grams (computed during training).
    """
    
    def __init__(self, n: int = 3, k: float = 0.1):
        """
        Initialize N-gram model with specified parameters.
        
        Parameters
        ----------
        n : int, optional
            Size of n-grams to use (e.g., 3 for trigrams). Default is 3.
        k : float, optional
            Smoothing parameter for add-k (Laplace) smoothing. Higher values
            give more weight to unseen n-grams. Default is 0.1.
        """
        self.n = n
        self.k = k
        self.counts = {}
        self.total = 0
        self.log_probs = {}
        self.floor = None

    def normalise(self, text):
        """
        Normalize text to uppercase alphabetic characters only.
        
        Removes all non-alphabetic characters and converts to uppercase.
        Used for preprocessing text before n-gram extraction.
        
        Parameters
        ----------
        text : str
            Input text to normalize.
        
        Returns
        -------
        str
            Normalized text containing only uppercase letters A-Z.
        
        Examples
        --------
        >>> model = NGramModel()
        >>> model.normalise("Hello, World! 123")
        'HELLOWORLD'
        """
        return ''.join(ch for ch in text.upper() if 'A' <= ch <= 'Z')

    def train(self, corpus_text: str):
        """
        Train the n-gram model on a corpus of text.
        
        Counts all n-grams in the corpus and pre-computes log probabilities
        using add-k smoothing. Also computes the floor probability for
        unseen n-grams.
        
        Parameters
        ----------
        corpus_text : str
            Training corpus text. Can contain any characters; will be
            normalized automatically.
        
        Notes
        -----
        If the normalized corpus is shorter than n characters, the model
        will be initialized with empty counts and a floor value of -1e9.
        
        The probability of an n-gram is calculated as:
        P(ngram) = (count(ngram) + k) / (total + k * V)
        where V = 26^n is the vocabulary size.
        """
        cleaned_corpus = self.normalise(corpus_text)
        self.counts = {}
        self.log_probs = {}
        self.total = 0

        # edge case: text shorter than n
        if len(cleaned_corpus) < self.n:
            self.log_probs = {}
            self.floor = -1e9
            return
        
        # counting n-grams
        for i in range(len(cleaned_corpus) - self.n + 1):
            gram = cleaned_corpus[i:i+self.n]
            self.counts[gram] = self.counts.get(gram, 0) + 1
            self.total += 1

        V = 26**self.n # total number of possible trigrams over A-Z
        denom = self.total + self.k*V # denominator for add-k smoothing

        # precompute log probs for all seen ngrams
        for ng, count in self.counts.items():
            self.log_probs[ng] = log((count + self.k) / denom)
        
        # compute floor prob from unseen ngrams
        self.floor = log(self.k / denom)

    def score(self, text: str):
        """
        Score text using the trained n-gram model.
        
        Calculates the log probability of the text by summing the log
        probabilities of all n-grams in the text. Higher scores indicate
        more likely (better) text according to the model.
        
        Parameters
        ----------
        text : str
            Text to score. Can contain any characters; will be normalized
            automatically.
        
        Returns
        -------
        float
            Log probability score of the text. Higher values indicate
            better text quality. Returns -1e9 if text is shorter than n
            characters after normalization.
        
        Notes
        -----
        The score is the sum of log probabilities of all n-grams in the
        text. Unseen n-grams use the floor probability computed during
        training.
        
        Examples
        --------
        >>> model = NGramModel()
        >>> model.train("THE QUICK BROWN FOX")
        >>> score = model.score("THE QUICK BROWN")
        >>> isinstance(score, float)
        True
        """
        clean_text = self.normalise(text)

        # edge case for if length of text is < n
        if len(clean_text) < self.n:
            return -1e9
        
        total_score = 0

        for i in range(len(clean_text) - self.n + 1):
            gram = clean_text[i:i+self.n]

            if gram in self.log_probs:
                total_score += self.log_probs[gram]
            else:
                total_score += self.floor
        
        return total_score