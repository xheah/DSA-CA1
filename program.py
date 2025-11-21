import os
import time
import threading
import sys
import string
import textwrap
from pathlib import Path
from math import gcd
from Ciphers.keyword_cipher import KeywordCipher
from Ciphers.caesar_cipher import CaesarCipher
from Ciphers.affine_cipher import AffineCipher
from Ciphers.vigenere_cipher import VigenereCipher
from letterFreq import LFD
from SmartKeyFinder.decrypter import Decrypter

class Program:
    """
    Main program class for cipher encryption/decryption and analysis.
    
    Provides a menu-driven interface for various cryptographic operations
    including encryption, decryption, frequency analysis, keyword inference,
    and n-gram based decryption.
    
    Attributes
    ----------
    menu : str
        Formatted menu string displaying available program options.
    """
    
    def __init__(self):
        """
        Initialize Program instance.
        
        Sets up the main menu string with all available program options.
        The menu is displayed to users for navigation.
        """
        self.menu = """
        Please select your choice: (1,2,3,4,5,6,7)\n
        1. Encrypt/Decrypt File\n
        2. Letter frequency distribution\n
        3. Infer cipher keyword\n
        4. Batch Decryption\n
        5. Encrypt/Decrypt File using different ciphers\n
        6. Decrypt using NGrams (monoalphabetic substitution ciphers only)\n
        7. Exit
        """

    # ========== UI METHODS ==========
    def display_title(self):
        """
        Display welcome title screen.
        
        Prints a formatted welcome message with program information
        in a bordered box. Waits for user to press Enter before continuing.
        
        Notes
        -----
        The title includes course information, program name, and author details.
        The display is 60 characters wide with asterisk borders.
        """
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
        """
        Display menu options and get user choice.
        
        Prints the main menu and prompts user for a choice. Validates
        that the choice is one of the available options (1-7).
        
        Returns
        -------
        str
            User's menu choice as a string ('1', '2', '3', '4', '5', '6', or '7').
        
        Notes
        -----
        Continues prompting until a valid choice is entered. Input is
        automatically stripped of whitespace.
        """
        print(self.menu)
        choice = ''
        while choice not in ['1', '2', '3', '4', '5', '6', '7']:
            choice = input('Enter choice: ').strip()
        return choice
    
    def exit_program(self):
        """
        Exit the program with a farewell message.
        
        Prints a goodbye message and terminates the program using exit().
        
        Notes
        -----
        This method calls exit() which terminates the Python interpreter.
        Use with caution as it will stop the entire program execution.
        """
        print('Bye, thanks for using ST1507 DSAA: Keyword Cipher Encrypted Message Analyzer')
        exit()
    
    def _wait_for_continue(self):
        """
        Wait for user to press Enter before continuing.
        
        Helper method to pause program execution and wait for user input.
        Used after displaying results or completing operations to allow
        user to read output before returning to menu.
        """
        input('Press Enter, to continue...')

    # ========== INPUT VALIDATION METHODS ==========
    def encrypt_or_decrypt(self):
        """
        Get encrypt or decrypt choice from user.
        
        Prompts user to choose between encryption ('E') or decryption ('D').
        Validates input and continues prompting until valid choice is provided.
        
        Returns
        -------
        str
            Either 'E' for encrypt or 'D' for decrypt (uppercase).
        
        Notes
        -----
        Input is automatically converted to uppercase and stripped of whitespace.
        """
        option = ''
        while option not in ['E', 'D']:
            option = input('Enter "E" for Encrypt or "D" for Decrypt: ').upper()
        return option
    
    def get_keyword(self):
        """
        Get and validate keyword from user.
        
        Prompts user for a keyword and validates that it contains only
        alphabetic characters. Continues prompting until valid keyword provided.
        
        Returns
        -------
        str
            Valid keyword containing only letters.
        
        Notes
        -----
        The keyword is stripped of leading/trailing whitespace. Non-alphabetic
        characters (including spaces, numbers, punctuation) are not allowed.
        """
        while True:
            keyword = input('Enter the keyword: ').strip()
            if not keyword.isalpha():
                print("Keyword must contain only letters. Please try again.\n")
                continue
            return keyword

    # ========== FILE I/O METHODS ==========
    def get_file_ED(self, ed: str):
        """
        Get file content for encryption or decryption.
        
        Prompts user for a filename and reads its contents. The prompt
        message adapts based on whether encrypting or decrypting.
        
        Parameters
        ----------
        ed : str
            Either 'E' for encrypt or 'D' for decrypt. Determines the
            prompt message displayed to user.
        
        Returns
        -------
        str
            Contents of the file as a string.
        
        Notes
        -----
        Continues prompting until a valid file is found. Handles
        FileNotFoundError gracefully by re-prompting.
        """
        choice = 'encrypt' if ed.upper() == 'E' else 'decrypt'
        while True:
            input_file_name = input(f'Please enter the file you want to {choice}: ')
            try:
                with open(input_file_name, 'r') as file:
                    return file.read()
            except FileNotFoundError:
                print('File not found. Please try again.\n')
    
    def get_input_file(self):
        """
        Get input file for analysis.
        
        Prompts user for a filename and reads its contents for use in
        analysis operations (e.g., frequency distribution, keyword inference).
        
        Returns
        -------
        str
            Contents of the file as a string.
        
        Notes
        -----
        Continues prompting until a valid file is found. Handles
        FileNotFoundError gracefully by re-prompting.
        """
        while True:
            filename = input('Please enter the file you want to analyse: ')
            try:
                with open(filename, 'r') as f:
                    return f.read()
            except FileNotFoundError:
                print('File not found. Please try again.\n')

    def get_output_file(self):
        """
        Get output filename from user with validation.
        
        Prompts user for an output filename and validates that it:
        - Is at least 4 characters long
        - Ends with '.txt' extension
        - Either doesn't exist or user confirms overwrite
        
        Returns
        -------
        str
            Valid output filename that can be used for writing.
        
        Notes
        -----
        If the file already exists, user is prompted to confirm overwrite.
        If user declines, they must enter a different filename.
        """
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
        """
        Get keyword file content from user.
        
        Prompts user for a filename containing keyword candidates and
        reads its contents. Used for keyword inference operations.
        
        Returns
        -------
        str
            Contents of the keyword file as a string (typically
            newline-separated keywords).
        
        Notes
        -----
        Continues prompting until a valid file is found. Handles
        FileNotFoundError gracefully by re-prompting.
        """
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
        """
        Get folder path from user for batch operations.
        
        Prompts user for a folder name and validates that:
        - The folder exists in the script's directory
        - The folder is not empty
        
        Returns
        -------
        Path
            Path object pointing to the validated folder.
        
        Notes
        -----
        The folder is resolved relative to the script's parent directory.
        Empty folders are rejected and user must provide a different folder.
        """
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
        """
        Get keyword list file from within a specified folder.
        
        Prompts user for a filename and validates that it exists within
        the given folder path. Used for batch decryption operations.
        
        Parameters
        ----------
        folder_path : Path
            Path object pointing to the folder containing the keyword file.
        
        Returns
        -------
        Path
            Path object pointing to the validated keyword file.
        
        Notes
        -----
        Continues prompting until a file that exists in the specified
        folder is provided.
        """
        while True:
            filename = input('Please enter the keyword file: ').strip()
            if (folder_path / filename).is_file():
                return folder_path / filename
            else:
                print('The file does not exist')
                continue

    def get_caesar_shift(self):
        """
        Get Caesar cipher shift value from user.
        
        Prompts user for an integer shift value and validates the input.
        Continues prompting until a valid integer is provided.
        
        Returns
        -------
        int
            Shift value for Caesar cipher encryption/decryption.
        """
        while True:
            try:
                shift = int(input('Please enter the value of the shift: '))
                return shift
            except ValueError:
                print('Please enter a valid number')
                continue
    
    def get_affine_key(self) -> list[int]:
        """
        Get affine cipher key values (a, b) from user.
        
        Prompts user for two integers 'a' and 'b' that form the affine
        cipher key. Validates that 'a' is coprime with 26 (required for
        affine cipher to be invertible).
        
        Returns
        -------
        list of int
            Two-element list [a, b] representing the affine cipher key.
        
        Notes
        -----
        The value 'a' must be coprime with 26 (gcd(a, 26) = 1) for the
        affine cipher to be valid. The function will continue prompting
        until valid values are provided.
        """
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

    def get_crack_method(self) -> str:
        """
        Get decryption method choice from user.
        
        Prompts user to choose between hill climbing and simulated annealing
        optimization methods for n-gram based decryption.
        
        Returns
        -------
        str
            Either 'hill' for hill climbing or 'anneal' for simulated annealing.
        
        Notes
        -----
        User input is case-insensitive. Valid inputs are 'H' or 'SA'.
        """
        while True:
            method = input("Please enter the method to crack the ciphertext ('H' for hill climbing and 'SA' for simulated annealing): ")
            method = method.strip().upper()
            if method not in ['H', 'SA']:
                print('Please enter a valid method')
                continue
            return 'hill' if method == 'H' else 'anneal'
        
    def loading_animation(self, stop_event: threading.Event, delay: float = 0.3):
        """
        Display animated loading indicator in a separate thread.
        
        Prints an animated "Decrypting", "Decrypting.", "Decrypting..",
        "Decrypting..." pattern that cycles until the stop event is set.
        Designed to run in a daemon thread during long operations.
        
        Parameters
        ----------
        stop_event : threading.Event
            Event object that signals when to stop the animation.
        delay : float, optional
            Delay in seconds between animation frame updates.
            Default is 0.3.
        
        Notes
        -----
        This method is intended to be run in a separate thread. It will
        continue until stop_event.is_set() returns True. The animation
        clears itself when stopped.
        """
        patterns = ["", ".", "..", "..."]
        idx = 0

        while not stop_event.is_set():
            dots = patterns[idx]
            sys.stdout.write('\rDecrypting' + dots + '   ')
            sys.stdout.flush()

            idx = (idx + 1) % len(patterns)
            time.sleep(delay)
        
        sys.stdout.write('\r' + ' ' * (len('Loading') + 5) + '\r')
        sys.stdout.flush()

    def format_key_mapping(self, key) -> str:
        """
        Format substitution key mapping for display.
        
        Creates a two-row formatted string showing the mapping between
        ciphertext and plaintext letters in a readable format.
        
        Parameters
        ----------
        key : str or dict of {str: str}
            If str: 26-character string where key[i] represents the plaintext letter
            that corresponds to ciphertext letter chr(ord('A') + i).
            If dict: Dictionary mapping ciphertext letters (uppercase) to plaintext
            letters (uppercase).
        
        Returns
        -------
        str
            Formatted string with two lines:
            - First line: "CIPHER: A B C D ..."
            - Second line: "PLAIN : [mapped letters]"
        
        Examples
        --------
        >>> prog = Program()
        >>> key = "ZYXWVUTSRQPONMLKJIHGFEDCBA"
        >>> result = prog.format_key_mapping(key)
        >>> "CIPHER:" in result
        True
        """
        cipher_row = "CIPHER: " + " ".join(string.ascii_uppercase)
        # Handle both string and dict formats
        if isinstance(key, dict):
            key_str = ''.join(key[c] for c in string.ascii_uppercase)
        else:
            key_str = key
        plain_row  = "PLAIN : " + " ".join(key_str)
        return cipher_row + "\n" + plain_row
    
    def get_yn(self, message: str):
        """
        Get yes/no input from user with validation.
        
        Prompts the user with a message and validates that the response
        is either 'Y' or 'N' (case-insensitive). Continues prompting
        until valid input is received.
        
        Parameters
        ----------
        message : str
            Message to display to the user before the (Y/N) prompt.
        
        Returns
        -------
        str
            Either 'Y' or 'N' (uppercase).
        
        Notes
        -----
        Input is automatically converted to uppercase and stripped of
        whitespace. Invalid inputs will cause the prompt to repeat.
        """
        while True:
            yn = input(f'{message} (Y/N): ')
            yn = yn.strip().upper()
            if yn not in ['Y', 'N']:
                print('Please enter a valid option')
                continue
            return yn

    def display_ngram_results(self, results: dict):
        """
        Display n-gram decryption results in a formatted output.
        
        Prints the decryption results including score, key mapping, and
        decrypted plaintext. For long plaintext, offers option to view
        full text after showing a preview.
        
        Parameters
        ----------
        results : dict
            Dictionary containing decryption results with keys:
            - "best_score" : float
                Score of the best decryption key found.
            - "best_key" : dict of {str: str}
                Best decryption key mapping (ciphertext -> plaintext).
            - "best_plaintext" : str
                Decrypted plaintext using the best key.
        
        Notes
        -----
        If the plaintext is longer than 800 characters, it will be
        truncated with an option for the user to view the full text.
        Empty plaintext will display "[No Plaintext Produced]".
        """
        best_score = results["best_score"]
        best_key = results["best_key"]
        best_plaintext = results["best_plaintext"]

        print("="*60)
        print(" N-GRAM DECRYPTION RESULT".center(60))
        print("="*60)

        print(f"Best Score: {best_score:.2f}")

        print("\nKey Mapping:")
        key_str = ''.join(best_key[c] for c in string.ascii_uppercase)
        print(self.format_key_mapping(key_str))

        print('\nDecrypted Plaintext (preview): ')
        preview = best_plaintext.strip()
        if not preview:
            print("[No Plaintext Produced]")
        else:
            wrapped = textwrap.fill(preview, width=60)
            max_chars = 800
            if len(preview) > max_chars:
                print(wrapped[:max_chars])
                print('\n[...output truncated]')
                yn = self.get_yn('View full text?')
                if yn == 'Y':
                    print(wrapped)
            else:
                print(wrapped)
        
        print('='*60)
        
    # ========== BUSINESS LOGIC METHODS ==========
    def _handle_encrypt_decrypt(self):
        """
        Handle menu option 1: Encrypt/Decrypt File.
        
        Performs encryption or decryption of a file using Keyword Cipher.
        Prompts user for operation type, input file, keyword, and output file.
        Writes the result to the output file.
        
        Notes
        -----
        This method handles the complete workflow:
        1. Get encrypt/decrypt choice
        2. Get input file content
        3. Get keyword
        4. Get output filename
        5. Perform encryption/decryption
        6. Write result to file
        """
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
        """
        Handle menu option 2: Letter frequency distribution.
        
        Analyzes a file and displays a visual frequency distribution graph
        showing the percentage of each letter in the text.
        
        Notes
        -----
        Creates an LFD (Letter Frequency Distribution) object and prints
        its string representation, which includes a bar graph visualization.
        """
        content = self.get_input_file()
        lfd = LFD(content)
        print(lfd)
        self._wait_for_continue()
    
    def _handle_infer_keyword(self):
        """
        Handle menu option 3: Infer cipher keyword.
        
        Attempts to infer the keyword used to encrypt a file by comparing
        frequency distributions with a list of candidate keywords. If a
        keyword is found, offers to decrypt the file using that keyword.
        
        Notes
        -----
        This method:
        1. Gets input file content
        2. Gets keyword candidate file
        3. Uses frequency analysis to infer the most likely keyword
        4. If keyword found, offers to decrypt and save result
        5. If no keyword found, displays appropriate message
        """
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
        """
        Handle menu option 4: Batch Decryption.
        
        Performs batch decryption of multiple files in a folder. For each
        file (except the keyword file), infers the keyword and decrypts it,
        saving results with '_decr.txt' suffix. Creates a log file documenting
        all decryption operations.
        
        Notes
        -----
        This method:
        1. Gets folder path containing encrypted files
        2. Gets keyword candidate file from folder
        3. For each file in folder (excluding keyword file):
           - Infers keyword using frequency analysis
           - Decrypts file if keyword found
           - Saves decrypted file with '_decr.txt' suffix
        4. Creates 'log.txt' file documenting all operations
        
        Files where no keyword is found are skipped and logged.
        """
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
        """
        Handle menu option 5: Encrypt/Decrypt using different ciphers.
        
        Allows user to select from multiple cipher types (Keyword, Caesar,
        Affine, Vigenere) and perform encryption or decryption operations.
        Prompts for cipher selection, operation type, input file, and output file.
        
        Notes
        -----
        Each cipher type requires different parameters:
        - Keyword Cipher: requires a keyword
        - Caesar Cipher: requires a shift value
        - Affine Cipher: requires two values (a, b) where a is coprime with 26
        - Vigenere Cipher: requires a key string
        """
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

    def _handle_ngram_decryption(self):
        """
        Handle menu option 6: Decrypt using n-grams.
        
        Performs decryption of monoalphabetic substitution ciphers using
        n-gram language models and optimization algorithms (hill climbing
        or simulated annealing). Displays results and optionally saves
        decrypted text to a file.
        
        Notes
        -----
        This method:
        1. Gets ciphertext from user
        2. Prompts for optimization method (hill climbing or simulated annealing)
        3. Runs decryption with loading animation
        4. Displays results including score, key mapping, and plaintext
        5. Optionally saves decrypted text to file
        
        The decryption uses 10 random restarts by default to avoid local optima.
        """
        ciphertext = self.get_input_file()
        method = self.get_crack_method()
        input("Press Enter to begin decryption...")
        d = Decrypter()

        stop_event = threading.Event()
        spinner_thread = threading.Thread(
            target=self.loading_animation,
            args=(stop_event,),
            daemon=True
        )
        spinner_thread.start()

        try:
            results = d.crack(ciphertext, method, 10)
        finally:
            stop_event.set()
            spinner_thread.join()

        print()
        self.display_ngram_results(results)
        yn = self.get_yn('Would you like to write the decrypted text into an output file?')
        if yn == "Y":
            output_file = self.get_output_file()
            with open(output_file, 'w') as f:
                f.write(results["best_plaintext"])

        self._wait_for_continue()

    # ========== MAIN RUN METHOD ==========
    def run(self):
        """
        Main program loop.
        
        Displays the welcome title and enters an infinite loop that:
        1. Displays menu options
        2. Gets user choice
        3. Executes the selected operation
        4. Returns to menu (except for exit)
        
        Notes
        -----
        The loop continues until the user selects option 7 (Exit), which
        calls exit_program() and terminates the application.
        
        Menu options:
        - 1: Encrypt/Decrypt File (Keyword Cipher)
        - 2: Letter frequency distribution
        - 3: Infer cipher keyword
        - 4: Batch Decryption
        - 5: Encrypt/Decrypt using different ciphers
        - 6: Decrypt using NGrams
        - 7: Exit program
        """
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
                case '6': # Decrypt substitution cipher without keyword list
                    self._handle_ngram_decryption()
                case '7':
                    self.exit_program()