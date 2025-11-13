from Ciphers.keyword_cipher import KeywordCipher
from pathlib import Path
def all_encrypts():
    para1 = """Jane, I will not trouble you with abominable details: some strong words 
    shall express what I have to say.  I lived with that woman upstairs four years, and 
    before that time she had tried me indeed: her character ripened and developed with 
    frightful rapidity; her vices sprang up fast and rank: they were so strong, only cruelty 
    could check them, and I would not use cruelty.  What a pigmy intellect she had, and what 
    giant propensities!  How fearful were the curses those propensities entailed on me!  
    Bertha Mason, the true daughter of an infamous mother, dragged me through all the hideous 
    and degrading agonies which must attend a man bound to a wife at once intemperate and unchaste."""

    para2 = """It could not have been ten seconds, and yet it seemed a long time that their 
    hands were clasped together.  He had time to learn every detail of her hand.  He explored 
    the long fingers, the shapely nails, the work-hardened palm with its row of callouses, 
    the smooth flesh under the wrist.  Merely from feeling it he would have known it by sight. 
    In the same instant it occurred to him that he did not know what colour the girl's eyes 
    were.  They were probably brown, but people with dark hair sometimes had blue eyes.  To turn 
    his head and look at her would have been inconceivable folly.  With hands locked together, 
    invisible among the press of bodies, they stared steadily in front of them, and instead of 
    the eyes of the girl, the eyes of the aged prisoner gazed mournfully at Winston out of nests 
    of hair."""

    para3 = """But I did not know how to make my apology. The words that had strung themselves
    so easily to make a blunder in the drawing room would not come now that I wished the blunder 
    remedied.  I stood there below her window, tongue-tied and ashamed.  Suddenly I saw her turn 
    and stretch behind her, and then she leant forward once again and threw something at me from 
    the window.  It struck me on the cheek and fell to the ground.  I stooped to pick it up.  
    It was one of the flowers from her bowl, an autumn crocus."""

    para4 = """Books bombarded his shoulder, his arms, his upturned face.  A book lit, almost 
    obediently, like a white pigeon, in his hands, wings fluttering.  In the dim, wavering 
    light, a page hung open and it was like a snowy feather, the words delicately painted thereon.  
    In all the rush and fervor, Montage had only an instant to read a line, but it blazed in his
    mind for the next minute as if stamped there with fiery steel.  “Time has fallen asleep in 
    the afternoon sunshine.”  He dropped the book.  Immediately, another fell into his arms."""

    apple = KeywordCipher('apple')
    geodude = KeywordCipher('geodude')
    megatron = KeywordCipher('megatron')
    rodtang = KeywordCipher('rodtang')
    script_dir = Path(__file__).parent
    case_dir = script_dir / "CASE01"
    jane = case_dir / 'JaneEyre.txt'
    nineteen84 = case_dir / 'nineteen84.txt'
    mycousinrachel = case_dir / 'mycousinrachel.txt'
    fahrenheit451 = case_dir / 'fahrenheit451.txt'

    jane.write_text(apple.encrypt(para1))
    nineteen84.write_text(rodtang.encrypt(para2))
    mycousinrachel.write_text(geodude.encrypt(para3))
    fahrenheit451.write_text(megatron.encrypt(para4))