import os
from pathlib import Path
from Ciphers.keyword_cipher import KeywordCipher
from letterFreq import LFD
from program import Program

def checking():
    text_path = Path(__file__).parent / 'CASE01' / 'fahrenheit451.txt'

    t = text_path.read_text()
    t_lfd = LFD(t)
    print(t_lfd.make_string())
    


if __name__ == '__main__':
    program = Program()
    program.run()