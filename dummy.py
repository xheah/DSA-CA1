import os
from pathlib import Path
from Ciphers.keyword_cipher import KeywordCipher
from letterFreq import LFD
# ============================================================================
# UI/DISPLAY FUNCTIONS
# ============================================================================

def display_title():
    width = 60
    lines = [
        "ST1507 DSAA: Welcome to:",
        "",
        "~ Keyword Cipher Encrypted Message Analyzer ~",
        "--------------------------------------------------------",
        "",
        "- Done by: Aden Cheah King Hern (123456)",
        "- Class DAAA/2B/21"
    ]
    print("*" * width)
    for line in lines:
        print("* " + line.center(width - 4) + " *")
    print("*" * width)
    print()
    input("Press Enter, to continue....")

def display_options():
    menu = """
    Please select your choice: (1,2,3,4,5,6,7)\n
    1. Encrypt/Decrypt File\n
    2. Letter frequency distribution\n
    3. Infer cipher keyword\n
    4. Batch Decryption\n
    5. Extra option one\n
    6. Extra option two\n
    7. Exit
    """
    print(menu)
    choice = ''
    while choice not in ['1', '2', '3', '4', '5', '6', '7']:
        choice = input('Enter choice: ').strip()
    return choice

def exit_program():
    print('Bye, thanks for using ST1507 DSAA: Keyword Cipher Encrypted Message Analyzer')
    exit()

# ============================================================================
# USER INPUT VALIDATION FUNCTIONS
# ============================================================================

def encrypt_or_decrypt():
    option = ''
    while option not in ['E', 'D']:
        option = input('Enter "E" for Encrypt or "D" for Decrypt: ').upper()
    return option

def get_keyword():
    while True:
        keyword = input('Enter the keyword: ').strip()
        if not keyword.isalpha():
            print("Keyword must contain only letters. Please try again.\n")
            continue
        return keyword

# ============================================================================
# FILE INPUT/OUTPUT FUNCTIONS
# ============================================================================

def get_file_ED(ed: str):
    choice = 'encrypt' if ed.upper() == 'E' else 'decrypt'
    while True:
        input_file_name = input(f'Please enter the file you want to {choice}: ')
        try:
            with open(input_file_name, 'r') as file:
                return file.read()
        except FileNotFoundError:
            print('File not found. Please try again.\n')

def get_input_file():
    while True:
        filename = input('Please enter the file you want to analyse: ')
        try:
            with open(filename, 'r') as f:
                return f.read()
        except FileNotFoundError:
            print('File not found. Please try again.\n')

def get_output_file():
    while True:
        output = input('Please enter an output file: ').strip()
        if len(output) < 4 or not output.endswith('.txt'):
            print('Please enter a valid file name.\n')
            continue
        if os.path.exists(output):
            overwrite = input(f"'{output}' already exists. Overwrite? (Y/N): ").strip().upper()
            if overwrite != 'Y':
                print("Please enter a different file name.\n")
                continue
        return output

def get_keyword_file():
    while True:
        filename = input('Please enter the keyword file: ').strip()
        try:
            with open(filename, 'r') as f:
                content = f.read()
                return content
        except FileNotFoundError:
            print('Please enter a valid file') 
            continue

# ============================================================================
# FOLDER/DIRECTORY FUNCTIONS
# ============================================================================

def get_folder_name():
    while True:
        foldername = input('Please enter the folder name: ').strip()
        if foldername == '':
            continue
        script_dir = Path(__file__).parent
        folder_path = script_dir / foldername
        if folder_path.is_dir():
            if next(folder_path.iterdir(), None) is None:
                print('Empty folder')
                continue
            else:
                return folder_path
        else:
            print('Folder does not exist, please enter again')
            continue

def get_keyword_list_file(folder_path: Path):
    while True:
        filename = input('Please enter the keyword file: ').strip()
        if (folder_path / filename).is_file():
            return folder_path / filename
        else:
            print('The file does not exist')
            continue

# ============================================================================
# MAIN PROGRAM
# ============================================================================

def main():
    display_title()
    while True:
        choice = display_options()
        match choice:
            case '1': # Encrypt/Decrypt
                e_or_d = encrypt_or_decrypt()
                original = get_file_ED(e_or_d)
                keyword = get_keyword()
                kw_cypher = KeywordCipher(keyword)
                output_file = get_output_file()
                if e_or_d.upper() == 'E':
                    encrypted = kw_cypher.encrypt(original)
                    with open(output_file, 'w') as f:
                        f.write(encrypted)
                elif e_or_d.upper() == 'D':
                    translated = kw_cypher.decrypt(original)
                    with open(output_file, 'w') as f:
                        f.write(translated)
                    
                input('Press Enter, to continue...')
                continue

            case '2': # Letter Frequency Distribution
                content = get_input_file()                
                lfd = LFD(content)
                lfd.display()
                input('Press Enter, to continue...')
                continue
            case '3': # infer keyword
                content = get_input_file()
                keyword_candidates = get_keyword_file().split('\n')
                lfd = LFD(content)
                inferred_keyword = lfd.infer_keyword(keyword_candidates)
                if inferred_keyword == '':
                    print('No keyword was found')
                    continue
                print(f'The inferred keyword is: {inferred_keyword}')
                yn = ''
                while yn not in ['Y', 'N']:
                    yn = input('Would you like to decrypt this file using this key? (Y/N) ').strip().upper()
                if yn == 'Y':
                    output_file = get_output_file()
                    with open(output_file, 'w') as f:
                        kwc = KeywordCipher(inferred_keyword)
                        f.write(kwc.decrypt(content))
                    input('Press Enter, to continue...')
                    continue
            case '4': # batch decryption
                folder_path = get_folder_name() # case01
                print()
                keyword_file = get_keyword_list_file(folder_path) # kw_cand_2.txt
                with open(keyword_file, 'r') as f:
                    keyword_list = f.read().split('\n')
                log = ''
                for file_path in folder_path.iterdir():
                    if file_path.is_file() and file_path != keyword_file: # if its a file and its not kw file
                        with open(file_path, 'r') as g:
                            content = g.read() # para in the file
                        lfd = LFD(content) # lfd for the para
                        keyword = lfd.infer_keyword(keyword_list) # the keyword inferred
                        filename = file_path.name # file name of the current iterated file
                        filestem = file_path.stem
                        output_filename = filestem + '_decr.txt'

                        log += f'Decrypting: {filename} with keyword: {keyword} as: {output_filename}\n'
                        print(f'Decrypting: {filename} with keyword: {keyword} as: {output_filename}', end='\n\n')

                        # decrypt and write to <filename>_decr in new_folder
                        kwc = KeywordCipher(keyword)
                        decrypted_text = kwc.decrypt(content)
                        output_path = folder_path / output_filename

                        with open(output_path, 'w') as out_file:
                            out_file.write(decrypted_text)
                log_path = folder_path / 'log.txt'
                with open(log_path, 'w') as log_file:
                    log_file.write(log)
                input('Press Enter, to continue...')
                continue
            case '5':
                pass
            case '6':
                pass
            case '7':
                exit_program()