class TextAnalyser:
    def __init__(self, text):
        self.__text = text
        self.__common_eng_bigrams = ['TH', 'HE', 'IN', 'ER', 'AN', 'RE', 'ON', 'AT', 'EN', 'ND']
        self.__common_eng_trigrams = ['THE', 'AND', 'ING', 'ENT', 'ION']
        self.__one_letters = ['A', 'I']
    
    def make_words(self):
        """Split the text into just words"""
        alpha_text = ''.join([ch for ch in self.__text if ch.isalpha() or ch.isspace()])
        words = alpha_text.split(' ')
        return words

    def find_unigrams(self):
        """Find all the single-letter words in text"""
        words = self.make_words()
        possible_unigrams = [w.upper() for w in words if len(w) == 1]
        count = {}
        for ch in possible_unigrams:
            if ch not in count:
                count[ch] = 1
            else:
                count[ch] += 1
        sorted_count = dict(sorted(count.items(), key = lambda x: x[1], reverse=True))
        return sorted_count
    
    def find_bigrams(self):
        """Find the most common two-letter combinations"""
        # Getting all the words
        words = self.make_words()
        possible_bigrams = {}
        for w in words:
            w = w.upper()
            if len(w) > 2:
                for i in range(len(w) - 2):
                    bigram = w[i] + w[i+1]
                    if bigram in possible_bigrams:
                        possible_bigrams[bigram] += 1
                    else:
                        possible_bigrams[bigram] = 1
            elif len(w) == 2:
                bigram = w
                if bigram in possible_bigrams:
                    possible_bigrams[bigram] += 1
                else:
                    possible_bigrams[bigram] = 1
        sorted_possible_bigrams = dict(sorted(possible_bigrams.items(), key = lambda x: x[1], reverse = True)[:10])
        return sorted_possible_bigrams
    
    def find_trigrams(self):
        words = self.make_words()
        possible_trigrams = {}
        for w in words:
            w = w.upper()
            if len(w) > 3:
                for i in range(len(w) - 3):
                    trigram = w[i] + w[i+1] + w[i+2]
                    if trigram not in possible_trigrams:
                        possible_trigrams[trigram] = 1
                    else:
                        possible_trigrams[trigram] += 1
            elif len(w) == 3:
                if trigram not in possible_trigrams:
                    possible_trigrams[trigram] = 1
                else:
                    possible_trigrams[trigram] += 1

        sorted_possible_trigrams = dict(sorted(possible_trigrams.items(), key = lambda x: x[1], reverse = True)[:5])
        return sorted_possible_trigrams

    def infer_mapping(self):
        one_letters = self.find_unigrams()
        bigrams = self.find_bigrams()
        trigrams = self.find_trigrams()
        assumption = {}

        for i, ch in enumerate(one_letters.keys()):
            if i < len(self.__one_letters):
                assumption[self.__one_letters[i]] = ch
        for bigram in bigrams:
            pass