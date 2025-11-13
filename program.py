import os
from pathlib import Path
from math import gcd
from Ciphers.keyword_cipher import KeywordCipher
from Ciphers.caesar_cipher import CaesarCipher
from Ciphers.affine_cipher import AffineCipher
from Ciphers.vigenere_cipher import VigenereCipher
from letterFreq import LFD

class Program:
    def __init__(self):
        self.menu = """
        Please select your choice: (1,2,3,4,5,6,7)\n
        1. Encrypt/Decrypt File\n
        2. Letter frequency distribution\n
        3. Infer cipher keyword\n
        4. Batch Decryption\n
        5. Encrypt/Decrypt File using different ciphers\n
        6. Decrypt using NGrams\n
        7. Exit
        """

    # ========== UI METHODS ==========
    def display_title(self):
        """Display welcome title"""
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
    
    def display_options(self):
        """Display menu and get user choice"""
        print(self.menu)
        choice = ''
        while choice not in ['1', '2', '3', '4', '5', '6', '7']:
            choice = input('Enter choice: ').strip()
        return choice
    
    def exit_program(self):
        """Exit the program"""
        print('Bye, thanks for using ST1507 DSAA: Keyword Cipher Encrypted Message Analyzer')
        exit()
    
    def _wait_for_continue(self):
        """Helper method to wait for user to continue"""
        input('Press Enter, to continue...')

    # ========== INPUT VALIDATION METHODS ==========
    def encrypt_or_decrypt(self):
        """Get encrypt/decrypt choice from user"""
        option = ''
        while option not in ['E', 'D']:
            option = input('Enter "E" for Encrypt or "D" for Decrypt: ').upper()
        return option
    
    def get_keyword(self):
        """Get and validate keyword from user"""
        while True:
            keyword = input('Enter the keyword: ').strip()
            if not keyword.isalpha():
                print("Keyword must contain only letters. Please try again.\n")
                continue
            return keyword

    # ========== FILE I/O METHODS ==========
    def get_file_ED(self, ed: str):
        """Get file content for encrypt/decrypt"""
        choice = 'encrypt' if ed.upper() == 'E' else 'decrypt'
        while True:
            input_file_name = input(f'Please enter the file you want to {choice}: ')
            try:
                with open(input_file_name, 'r') as file:
                    return file.read()
            except FileNotFoundError:
                print('File not found. Please try again.\n')
    
    def get_input_file(self):
        """Get input file for analysis"""
        while True:
            filename = input('Please enter the file you want to analyse: ')
            try:
                with open(filename, 'r') as f:
                    return f.read()
            except FileNotFoundError:
                print('File not found. Please try again.\n')

    def get_output_file(self):
        """Get output filename from user"""
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
        
    def get_keyword_file(self):
        """Get keyword file content"""
        while True:
            filename = input('Please enter the keyword file: ').strip()
            try:
                with open(filename, 'r') as f:
                    content = f.read()
                    return content
            except FileNotFoundError:
                print('Please enter a valid file') 
                continue

    def get_folder_name(self):
        """Get folder path from user"""
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

    def get_keyword_list_file(self, folder_path: Path):
        """Get keyword list file from folder"""
        while True:
            filename = input('Please enter the keyword file: ').strip()
            if (folder_path / filename).is_file():
                return folder_path / filename
            else:
                print('The file does not exist')
                continue

    def get_caesar_shift(self):
        """Get the shift for Caesar Cipher from user"""
        while True:
            try:
                shift = int(input('Please enter the value of the shift: '))
                return shift
            except ValueError:
                print('Please enter a valid number')
                continue
    
    def get_affine_key(self) -> list[int]:
        """Get the a, b key values for Affine Cipher from user"""
        key = []
        while True:
            a = input('Please enter the a value for Affine Key (must be coprime with 26): ')
            try:
                a = int(a)
                if gcd(a, 26) > 1:
                    print('a must be coprime with 26')
                    continue
                else:
                    key.append(a)
                    break
            except ValueError:
                print('Please enter a valid integer for a\n')
                continue
        while True:
            b = input('Please enter the b value for Affine Key: ')
            try:
                b = int(b)
                key.append(b)
                break
            except ValueError:
                print('Please enter a valid integer for b\n')
        return key 



    # ========== BUSINESS LOGIC METHODS ==========
    def _handle_encrypt_decrypt(self):
        """Handle menu option 1: Encrypt/Decrypt File"""
        e_or_d = self.encrypt_or_decrypt()
        original = self.get_file_ED(e_or_d)
        keyword = self.get_keyword()
        kw_cypher = KeywordCipher(keyword)
        output_file = self.get_output_file()
        
        if e_or_d.upper() == 'E':
            encrypted = kw_cypher.encrypt(original)
            with open(output_file, 'w') as f:
                f.write(encrypted)
        else:
            translated = kw_cypher.decrypt(original)
            with open(output_file, 'w') as f:
                f.write(translated)
        
        self._wait_for_continue()
    
    def _handle_frequency_distribution(self):
        """Handle menu option 2: Letter frequency distribution"""
        content = self.get_input_file()
        lfd = LFD(content)
        print(lfd)
        self._wait_for_continue()
    
    def _handle_infer_keyword(self):
        """Handle menu option 3: Infer cipher keyword"""
        content = self.get_input_file()
        keyword_candidates = self.get_keyword_file().split('\n')
        lfd = LFD(content)
        inferred_keyword = lfd.infer_keyword(keyword_candidates)
        
        if inferred_keyword == '':
            print('No keyword was found')
            return
        
        print(f'The inferred keyword is: {inferred_keyword}')
        yn = ''
        while yn not in ['Y', 'N']:
            yn = input('Would you like to decrypt this file using this key? (Y/N) ').strip().upper()
        
        if yn == 'Y':
            output_file = self.get_output_file()
            with open(output_file, 'w') as f:
                kwc = KeywordCipher(inferred_keyword)
                f.write(kwc.decrypt(content))
            self._wait_for_continue()
    
    def _handle_batch_decryption(self):
        """Handle menu option 4: Batch Decryption"""
        folder_path = self.get_folder_name()
        print()
        keyword_file = self.get_keyword_list_file(folder_path)
        
        with open(keyword_file, 'r') as f:
            keyword_list = f.read().split('\n')
        
        log = ''
        for file_path in folder_path.iterdir():
            if file_path.is_file() and file_path != keyword_file:
                with open(file_path, 'r') as g:
                    content = g.read()
                
                lfd = LFD(content)
                keyword = lfd.infer_keyword(keyword_list)
                if keyword == 'no keyword found':
                    print(keyword)
                    continue
                filestem = file_path.stem
                output_filename = filestem + '_decr.txt'
                
                log += f'Decrypting: {file_path.name} with keyword: {keyword} as: {output_filename}\n'
                print(f'Decrypting: {file_path.name} with keyword: {keyword} as: {output_filename}', end='\n\n')
                
                kwc = KeywordCipher(keyword)
                decrypted_text = kwc.decrypt(content)
                output_path = folder_path / output_filename
                
                with open(output_path, 'w') as out_file:
                    out_file.write(decrypted_text)
        
        log_path = folder_path / 'log.txt'
        with open(log_path, 'w') as log_file:
            log_file.write(log)
        
        self._wait_for_continue()
    
    def _handle_cipher_selection(self):
        cipher_select_menu = """Please select a cipher:
        1. Keyword Cipher
        2. Caesar Cipher
        3. Affine Cipher
        4. Vigenere Cipher"""
        while True:
            print(cipher_select_menu)
            chosen_cipher = input('Choice (1, 2, 3, 4): ').strip()
            if chosen_cipher not in ['1', '2', '3', '4']:
                print('Please enter a valid option.')
                continue
            match chosen_cipher:
                case '1':
                    keyword = self.get_keyword()
                    cipher = KeywordCipher(keyword)
                case '2':
                    shift = self.get_caesar_shift()
                    cipher = CaesarCipher(shift)
                case '3':
                    key = self.get_affine_key()
                    cipher = AffineCipher(key)
                case '4':
                    keyword = self.get_keyword()
                    cipher = VigenereCipher(keyword)
            e_or_d = self.encrypt_or_decrypt()
            original = self.get_file_ED(e_or_d)
            output_filename = self.get_output_file()
            if e_or_d == 'E':
                new_text = cipher.encrypt(original)
                with open(output_filename, 'w') as output_file:
                    output_file.write(new_text)
            else:
                new_text = cipher.decrypt(original)
                with open(output_filename, 'w') as output_file:
                    output_file.write(new_text)
            break
                
        
        self._wait_for_continue()

    # ========== MAIN RUN METHOD ==========
    def run(self):
        """Main program loop"""
        self.display_title()
        while True:
            choice = self.display_options()
            match choice: 
                case '1': # encrypt or decrypt given a keyword
                    self._handle_encrypt_decrypt()
                case '2': # print bar graph for fd
                    self._handle_frequency_distribution()
                case '3': # infer keyword given list of keywords in a file
                    self._handle_infer_keyword()
                case '4': # batch decrypt with folder and keyword file
                    self._handle_batch_decryption()
                case '5': # choose cipher and choose to encrypt or decrypt
                    self._handle_cipher_selection()
                case '6':
                    # Extra option two
                    pass
                case '7':
                    self.exit_program()