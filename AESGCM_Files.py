from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
import os

#Advanced Encryption Standards- Gallois Counter Mode (AESGCM)
key_folder = "keys.bin"

def load_or_createkey():
    #Checks if key already exists
    if os.path.exists(key_folder): 
        keybin = open((key_folder),"rb")
    #Stores read key in keys variable
        keys = keybin.read() 
        keybin.close()
    else:
    #Generates a 256 bit key
        keys = AESGCM.generate_key(bit_length = 256) 
    #Opens the bin file and stores the key there
        with open(key_folder, "wb") as f: 
            f.write(keys)
    return keys

#The parameters here are the data we want to encrypt and the key
def encrypt_data(file_path, key):
    #Generates 12 byte (96 bit) nonce
    nonce = os.urandom(12)
    #Reads the contents of the file
    with open(file_path, "rb") as file:
        words = file.read()
    print("ENCRYPT DEBUG → plaintext length:", len(words))

    
    #Creates a cipher object based on the key
    aes = AESGCM(key)
    
    #Encrypts the data
    ciphertext = aes.encrypt(nonce,words, None)
    
    #Combines nonce and cipher to be used later for 
    nonce_cipher = nonce + ciphertext
    
    #Updates file with encrypted data and nonce
    with open(file_path + ".enc","wb") as file:
        file.write(nonce_cipher)
    

#The parameters here are the file with encrypted file's nonce + ciphertext, and the key
def decrypt_data(enc_file, key): 
    with open(enc_file, "rb") as file:
        data = file.read()
    
    #Reads file to extract nonce and ciphertext
    nonce = data[:12]
    ciphertext = data[12:]
    
    #Creates cipher object based on key
    aes = AESGCM(key)
    
    #Integrity Check- trys to decrypt data but if data was modified or key is wrong, program crashes and doesn't write tampered data
    try:
        plaintext = aes.decrypt(nonce, ciphertext, None)
        print("DECRYPT DEBUG → plaintext length:", len(plaintext))
        print("DECRYPT DEBUG → first 100 bytes:", plaintext[:100])



    except InvalidTag:
        print("File Integrity Check failed- data was modified or key is wrong.")
        return
    
    file_path = "decrypted_data.txt"
    with open(file_path,"wb") as file:
        file.write(plaintext)
    return(file_path)


def main():
    #Generates key to use for encryption and decryption
    keys = load_or_createkey()
    user_input = ""
    
    #Feedback loop for encrypting and decrypting data
    while user_input != "x":
        user_input= input("### MAIN MENU ###\nWhat would you like to do?\ne- Encrypt\nd- Decrypt\nx-exit\n---->").lower()
        #Closes Program
        if user_input == "x":
            print("Closing Program...GOODBYE!")
        #Asks user for what they would like to encrypt then encrypts data
        elif user_input == "e":
            words = input("Please enter file path\n")
            encrypt_data(words, keys)
            print("Data Encrypted!")
        #Decrypts data
        elif user_input == "d":
            #Asks user for encrypted file, checks if it is an encrypted file, then decrypts data
            encrypted_file = input("Please enter a file path with Encrypted data: ")
            if encrypted_file.endswith(".enc"):
                print(decrypt_data(encrypted_file,keys))
                print("Data Decrypted!")
            else:
                print("Please enter a .enc file.")
        #Prints 'invalid input' if input isn't e,d, or x
        else:
            print("Invalid input! Try again")

if __name__ == "__main__":
    main()
