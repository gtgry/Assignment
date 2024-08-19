# # DOCUMENTATION
# # Amit Gautam
# # INFO-1249 Project 2 Cryptography Program
# # Description: This program can encode/decode Morse Code, encrypt/decrypt using a Caeser Cipher,
# #             and process files to decode/decrypt messages.


txt = "INFO-1249 Project 2!"

txt = txt.lower()

# Morse Code dictionary for encoding
englishToMorse = {
    'a': '.-', 'b': '-...', 'c': '-.-.', 'd': '-..', 'e': '.', 'f': '..-.', 'g': '--.', 
    'h': '....', 'i': '..', 'j': '.---', 'k': '-.-', 'l': '.-..', 'm': '--', 'n': '-.', 
    'o': '---', 'p': '.--.', 'q': '--.-', 'r': '.-.', 's': '...', 't': '-', 'u': '..-', 
    'v': '...-', 'w': '.--', 'x': '-..-', 'y': '-.--', 'z': '--..', '1': '.----', 
    '2': '..---', '3': '...--', '4': '....-', '5': '.....', '6': '-....', '7': '--...', 
    '8': '---..', '9': '----.', '0': '-----', ' ': '/'
}

mytable = str.maketrans(englishToMorse)
print(txt.translate(mytable))

morse_text = "... --- ... / ."

# Reverse Morse Code dictionary for decoding
morse_to_english = {
    '.-': 'a', '-...': 'b', '-.-.': 'c', '-..': 'd', '.': 'e', '..-.': 'f', 
    '--.': 'g', '....': 'h', '..': 'i', '.---': 'j', '-.-': 'k', '.-..': 'l', 
    '--': 'm', '-.': 'n', '---': 'o', '.--.': 'p', '--.-': 'q', '.-.': 'r', 
    '...': 's', '-': 't', '..-': 'u', '...-': 'v', '.--': 'w', '-..-': 'x', 
    '-.--': 'y', '--..': 'z', '.----': '1', '..---': '2', '...--': '3', 
    '....-': '4', '.....': '5', '-....': '6', '--...': '7', '---..': '8', 
    '----.': '9', '-----': '0', '/': ' '
}

#############
# choice 1
#
# sub_choice 1: Words to Morse code

print("CyPy-11824954 Cryptography Program")

def encode_to_morse(words):
    # Convert words to lowercase
    words = words.lower()
    morse = []

    # Iterate through each letter in the words
    for letter in words:
        if letter in englishToMorse:
            # Append the respective Morse code for the letter
            morse.append(englishToMorse[letter])
        else:
            return "Error: Invalid character found! Please enter only letters and numbers."
    
    # Join the Morse code list into a single string
    morse_code = ' '.join(morse)
    
    # Save the Morse code message to a file named 'message.txt'
    with open('message.txt', 'w') as a:
        a.write(morse_code)
    
    # Save the plain text to a file named 'planetext.txt'
    with open('planetext.txt', 'w') as a:
        a.write(words.capitalize())
    
    print(f"\nMessage saved to 'message.txt' and plain text saved to 'planetext.txt'")
    return morse_code
    
##########
# Encode/Decode Morse Code
# choice 1
# 
# sub_choice 2: Morse Code to normal words.

def decode_from_morse(morse_message):
    # Split Morse code text by ' / ' to get individual symbols
    morse_text_var = morse_message.strip().split(' ')
    words = []

    # Iterate through each Morse code symbol
    for symbol in morse_text_var:
        if symbol == '/':
            # Append space for ' / '
            words.append(' ')
        elif symbol in morse_to_english:
            # Append the respective English character for the Morse code
            words.append(morse_to_english[symbol])
        else:
            print("Error: Invalid Morse code found!")
            return
        
    # Join the English characters into a single string and capitalize the first letter.
    words = ''.join(words)
    return words.capitalize()
    
##################
# caesar cipher
#
# choice 2 
# sub_choice 1: Encrypting using Caesar Cipher.

def caesar(words, shift, encrypt=True):
    result = []
    for char in words: # Iterate through each character in the words
        if char.isalpha():
            # Calculate the shift amount within the range of 0-25
            shift_amount = shift % 26
            # Determine the starting ASCII value based on case
            start = ord('a') if char.islower() else ord('A')
            # Calculate the new character after shifting
            new_char = chr(start + (ord(char) - start + shift_amount) % 26)
            result.append(new_char)
        elif char is " ": # If the character is a space.
            print("Error: Space not allowed! Please enter only letters.")
            return

        else: # If the character is not a letter.
            print("Error: Invalid character found! Please enter only letters.")
            return
        
    # Join the encrypted characters into a single string
    if encrypt:
        encrypted_text = ''.join(result)
        print(f"Encrypted message: {encrypted_text}")
        # Save the plain text and encrypted message to the respective files
        with open('before encryption.txt', 'w') as a: # Save the plain text to a file named 'before encryption.txt'
            a.write(words.capitalize())
        with open('encrypted.txt', 'w') as a: # Save the encrypted message to a file named 'encrypted.txt'
            a.write(encrypted_text.capitalize())
        print(f"\nPlain text saved to before encryption.txt and encrypted message saved to encrypted.txt")
        return
    
    # Join the decrypted characters into a single string
    else:
        decrypted_text = ''.join(result)
        print(f"Decrypted message: {decrypted_text}")
        return

##################
# caesar cipher
#
# choice 2 
# sub_choice 2: Decrypting using Caesar Cipher.

def caesar_decrypt(words, shift):
    # Decrypt by shifting in the opposite direction
    decrypted_text = caesar(words, -shift, encrypt=False)
    return

#################
# File Processing
# choice 3

def process_files(alphabet_file, message_file, output_file):

    ###Process files for decryption."
    try:
        # Normalize file paths to correct any wrong slashes
        alphabet_file = alphabet_file.replace('\\', '/')
        message_file = message_file.replace('\\', '/')
        output_file = output_file.replace('\\', '/')


        # Read the alphabet file
        with open(alphabet_file, 'r') as a:
            alphabet = a.read().strip()

        # Check that the alphabet file contains exactly 26 characters.
        if len(alphabet) != 26:
            print("Error: Alphabet file must contain exactly 26 characters.")
            return
        
        # Read the message file
        with open(message_file, 'r') as a:
            morse_message = a.read().strip()

        # Decode the message file
        decoded_message = decode_from_morse(morse_message)
        if decoded_message is None:
            print("Error: Invalid Morse code in the message file.")
            return
        
        # Decrypt the decoded message using the alphabet file
        decrypted_message = ''.join(
            alphabet[ord(c) - ord('a')] if 'a' <= c <= 'z' else c for c in decoded_message.lower()
        )
        
        # Save the decrypted message to the output file (Overwrite if already exists)
        with open(output_file, 'w') as a:
            a.write(decrypted_message.capitalize())
        print(f"Decrypted message saved to {output_file}")
        return
    
    except FileNotFoundError:
        # error handler where one or more files are not found
        print("Error: One or more files not found.")
    except Exception as e:
        # error handler where other exceptions that may occur and print the error message
        print(f"An error occurred: {str(e)}")

def ensure_txt_extension(file_path):
    # Check if the file path does not end with '.txt'
    if not file_path.endswith('.txt'):
        # Append '.txt' to the file path if it doesn't already have it
        file_path += '.txt'
    # Return the modified or original file path
    return file_path

##################
#
#  
#  Main program loop for the cryptography tool.
#
###################
def main():
    while True:
        # Display menu options
        print("\nSelect an option:")
        print("1: Encode/Decode Morse Code")
        print("2: Encrypt/Decrypt using Caesar Cipher")
        print("3: File Processing")
        print("4: Exit")

        # Get user choice
        choice = input("Enter your choice: ")
        
        ######
        # Morse Code options

        if choice == '1':
            print()
            print("1 for encoding:", "2 for decode:", "3 to go back to main menu:", sep='\n')
            sub_choice = input("Enter your choice: ")
            if sub_choice == '1':
                words = input("\nEnter text to encode: ")
                print('\n',encode_to_morse(words))
            elif sub_choice == '2':
                morse_text = input("\nEnter Morse code to decode: ")
                print(decode_from_morse(morse_text))
            elif sub_choice == '3':
                main()
            else:
                print("\nInvalid option!")
        
        #####
        # Caesar Cipher options

        elif choice == '2':
            print()
            print("1 for Encrypting", "2 for Decrypting: ", "3 to go back to main menu.", sep='\n')
            sub_choice = input("What would you like to do? ")
            if sub_choice == '1' or sub_choice == '2':
                try:
                    shift = int(input("Enter the shift value: "))
                    if sub_choice == '1':
                        words = input("Enter text to encrypt: ")
                        caesar(words,shift,)
                        print()

                    elif sub_choice == '2':
                        words = input("Enter text to decrypt: ")
                        caesar_decrypt(words, shift)
                        print()
                except:
                    print("Invalid shift value! Please enter an integer.")
            elif sub_choice == '3':
                main
            else:
                print("Invalid option!")

        #######
        # File Processing options

        elif choice == '3':
            print()
            alphabet_file = input("Enter the alphabet file path: (default file: 'alphabet.txt')") or 'alphabet.txt'
            message_file = input("Enter the message file path: (default file: 'message.txt')") or 'message.txt'
            output_file = input("Enter the path for the output file: (default: 'planetext.txt') ") or 'planetext.txt'
            
            # Ensure the files have .txt extension
            alphabet_file = ensure_txt_extension(alphabet_file) 
            message_file = ensure_txt_extension(message_file)   
            output_file = ensure_txt_extension(output_file) 
            process_files(alphabet_file, message_file, output_file)

        ######
        # Exit the program
        elif choice == '4':
            print("CyPy-11824954\n")
            break

        # If user enters an empty string, prompt again
        elif choice == "":
            continue
        
        # If user enters an invalid choice, prompt again
        else:
            print("\nInvalid choice! Please select a valid option.")

if __name__ == "__main__":
    main()