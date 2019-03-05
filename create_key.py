from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from base64 import b64decode, b64encode
import sys


class Create_key:
    
    def __init__(self):
        new_key = RSA.generate(2048)
        self.public_key = new_key.publickey().exportKey()
        self.secret_key = new_key.exportKey(passphrase = None)
        print(self.public_key)
        print(self.secret_key)
        print(type(self.secret_key))
        # 秘密鍵作成
        with open('private2.pem', 'wb') as f:
            f.write(self.secret_key)
        
        # 公開鍵作成
        with open('public2.pem', 'wb') as f:
            f.write(self.public_key)
                
if __name__ == '__main__':
    
    print('start')
    keys = Create_key()
