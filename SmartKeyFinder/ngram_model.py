from math import log
class NGramModel:
    def __init__(self, n: int = 3, k: float = 0.1):
        self.n = n
        self.k = k
        self.counts = {}
        self.total = 0
        self.log_probs = {}
        self.floor = None

    def normalise(self, text):
        """Normalise the text to all uppercase alphabet"""
        return ''.join(ch for ch in text.upper() if 'A' <= ch <= 'Z')

    def train(self, corpus_text: str):
        """Count n-grams and pre-compute log probabilities and floor"""
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