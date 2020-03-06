import json
from base64 import b64encode, b64decode
from pprint import pprint

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15


class ITKoin:
    def __init__(self):
        self.pending_transactions = []
        self.unspent_transactions = []
        self.sender_inputs = []
        self.chain = []

    @staticmethod
    def generate_rsa_key(filename):
        rsakey =  RSA.generate(2048) # generálj 2048 bites RSA kulcsot
        rsapublickey = rsakey.publickey() # a kulcs publikus része kerüljön ide
        # print(rsakey)
        # pprint(rsakey)
        # print(vars(rsakey))
        # pprint(vars(rsakey))
        pprint(vars(rsakey))
        pprint(vars(rsapublickey))
        PEMrsakey = rsakey.export_key() # PEM formátumra alakítsd az RSA kulcsot
        pprint(PEMrsakey)
        PEMrsapublickey = rsapublickey.export_key() # PEM formátumra alakítsd a kulcs publikus részét
        pprint(PEMrsapublickey)
        privatekeyfilename = filename + 'priv.pem'
        f = open(privatekeyfilename, 'wb')
        f.write(PEMrsakey)
        f.close()
        publickeyfilename = filename + 'pub.pem'
        f = open(publickeyfilename, 'wb')
        f.write(PEMrsapublickey)
        f.close()
        return

    @staticmethod
    def create_hashobject(data):
        stringdump = json.dumps(data)  # ez nem teljesen korrekt megoldás, de így egyszerű mindent byte stringgé konvertálni
        binarydump = stringdump.encode()
        hashobject = SHA256.new() # hozz létre egy hash objektumot
        # töltsd be az objektumba a lenyomatolni kívánt byte stringet
        hashobject.update(binarydump)
        hashhexvalue = hashobject.hexdigest() # számítsd ki a lenyomatot, hexa kódolással
        print(hashhexvalue)
        return hashobject

    def load_key(self, filename):
        privatekeyfilename = filename + 'priv.pem'
        privatekeyfileobject = open(privatekeyfilename, 'r')
        privatekeyfilecontent = privatekeyfileobject.read()
        pprint(privatekeyfilecontent)
        rsakey = RSA.import_key(privatekeyfilecontent) # olvasd be a kulcsot
        self.rsakey = rsakey
        pprint(vars(self.rsakey))
        # rsapublickey = # a kulcs publikus része kerüljön ide
        # self.rsapublickey = rsapublickey
        # pprint(vars(self.rsapublickey))
        return

    def load_public_key(self, filename):
        publickeyfilename = filename + 'pub.pem'
        publickeyfileobject = open(publickeyfilename, 'r')
        publickeyfilecontent = publickeyfileobject.read()
        pprint(publickeyfilecontent)
        rsakey = RSA.import_key(publickeyfilecontent) # olvasd be a kulcsot
        rsapublickey = rsakey.publickey() # a kulcs publikus része kerüljön ide
        self.rsapublickey = rsapublickey
        pprint(vars(self.rsapublickey))
        return

    def create_signature(self, data):
        signatureobject = pkcs1_15.new(self.rsakey) # hozz létre egy signature objektumot
        hashobject = self.create_hashobject(data)  # az adatot töltsd be egy hash objektumba a create_hashobject(data) használatával
        signaturevalue = signatureobject.sign(hashobject) # készítsd el az aláírás értéket a sign függvénnyel
        print(signaturevalue)
        b64signaturevalue = b64encode(signaturevalue) # kódold base64 kódolással
        print(b64signaturevalue)
        print(b64signaturevalue.decode())
        return b64signaturevalue

    def verify_signature(self, data, b64signaturevalue, rsapublickey):
        verifyobject = pkcs1_15.new(rsapublickey)  # hozz létre egy verify objektumot
        hashobject = self.create_hashobject(data) # az adatot töltsd be egy hash objektumba a create_hashobject(data) használatával
        signaturevalue = b64decode(b64signaturevalue)  # dekódold base64 kódolással az aláírás értéket

        try:
            verifyobject.verify(hashobject, signaturevalue+1)
            validsignature = True
        except ValueError:
            signatureerror =  "Invalid signature" # ellenőrizd az aláírást
            validsignature = False
            print(signatureerror)

        return validsignature


ITKoin.generate_rsa_key("RSA")
coin = ITKoin()
ITKoin.load_key(coin, "RSA")
ITKoin.load_public_key(coin, "RSA")

signature = coin.create_signature("ASD")
coin.verify_signature("ASD", signature, coin.rsapublickey)