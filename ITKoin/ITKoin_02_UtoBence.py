from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import json
from base64 import b64encode, b64decode
from pprint import pprint
import pickle



class ITKoin:
    def __init__ (self):
        self.chain_filename = 'chain_01.txt'
        self.pending_transactions_filename = 'pending_01.txt'
        self.unspent_outputs_filename = 'unspent_01.txt'
        self.my_privatekey_filename = 'csmkey_03_priv.pem'
        self.chain = []
        self.pending_transactions = []
        self.unspent_outputs = []
        self.my_unspent_outputs = []
#        self.my_privatekey
#        self.my_publickey
#        self.my_id
        self.ITKoin_users = ['csmkey_03_id.txt', 'csmkey_04_id.txt'] # Ez egy lista, ahová s résztvevők id-jait tartalmazó file-neveket kell felsorolni
        self.initial_csaposhi_offering = 100


    def generate_rsa_key(self, filename): # a filenév tövével kell meghívni és három file-t generál: a privát és publikus kulcsoknak, ill. az ID-nak
        key = RSA.generate(2048)
        publickey = key.publickey()
        privatekey_filename = filename + '_priv.pem'
        f = open(privatekey_filename, 'wb')
        f.write(key.export_key())
        f.close()
        publickey_filename = filename + '_pub.pem'
        f = open(publickey_filename, 'wb')
        f.write(publickey.export_key())
        f.close()
        publickey_string = publickey.export_key().decode('ascii') # bináris stringet karakter stringgé konvertáljuk, hogy a json.dumps működjön rajta
        recipient_id_filename = filename + '_id.txt'
        f = open(recipient_id_filename, 'wb')
        f.write(self.create_hashhexvalue(publickey_string).encode('ascii')) # a hexa string hash értéket bináris stringgé konvertáljuk a file-ba íráshoz
        f.close()
        return

    def load_my_private_key (self):
        fileobject = open(self.my_privatekey_filename, 'r')
        self.my_privatekey = RSA.import_key(fileobject.read())
        self.my_publickey = self.my_privatekey.publickey()
        publickey_string = self.my_publickey.export_key().decode('ascii') # bináris stringet karakter stringgé konvertáljuk, hogy a json.dumps működjön rajta
        self.my_id = self.create_hashhexvalue(publickey_string) # a hexa string hash értéket bináris stringgé konvertáljuk a file-ba íráshoz
        pprint(self.my_id)
        return

    @staticmethod
    def load_public_key (filename):
        fileobject = open(filename, 'r')
        key = RSA.import_key(fileobject.read())
        return key.publickey()

    @staticmethod
    def load_id (filename):
        fileobject = open(filename, 'r')
        id = fileobject.read()
        return id

    @staticmethod
    def create_hashobject (data):
        stringdump = json.dumps(data)
        hashobject = SHA256.new(stringdump.encode())
        return hashobject

    @staticmethod
    def create_hashhexvalue (data):
        stringdump = json.dumps(data)
        hashobject = SHA256.new(stringdump.encode())
        return hashobject.hexdigest()

    @staticmethod
    def create_hashvalue (data):
        stringdump = json.dumps(data)
        hashobject = SHA256.new(stringdump.encode())
        return hashobject.digest()

    def create_signature (self, data):
        signatureobject = pkcs1_15.new(self.my_privatekey) # hozz létre egy signature objektumot
        hashobject = self.create_hashobject(data) # az adatot töltsd be egy hash objektumba a create_hashobject(data) használatával
        signaturevalue = signatureobject.sign(hashobject) # készítsd el az aláírás értéket a sign függvénnyel
        print(signaturevalue)
        b64signaturevalue = b64encode(signaturevalue) # kódold base64 kódolással
        print(b64signaturevalue)
        print(b64signaturevalue.decode())
        return b64signaturevalue.decode()

    def verify_signature(self, data, b64signaturevalue, rsapublickey):
        verifyobject = pkcs1_15.new(rsapublickey) # hozz létre egy verify objektumot
        hashobject = self.create_hashobject(data) # az adatot töltsd be egy hash objektumba a create_hashobject(data) használatával
        signaturevalue = b64decode(b64signaturevalue.encode()) # dekódold base64 kódolással az aláírás értéket
        signatureerror = verifyobject.verify(hashobject, signaturevalue) # ellenőrizd az aláírást
        validsignature = not signatureerror # értéke: True, ha az aláírás érvényes
        return validsignature

    @staticmethod
    def save_list(list, filename):
        f = open(filename, 'wb')
        pickle.dump(list, f)
        f.close()
        return

    def load_chain(self):
        fileobject = open(self.chain_filename, 'rb')
        self.chain = pickle.load(fileobject)
        pprint(self.chain)
        return

    def load_pending_transactions(self):
        fileobject = open(self.pending_transactions_filename, 'rb')
        self.pending_transactions = pickle.load(fileobject)
        pprint(self.pending_transactions)
        validated_pending_transactions = []
        while len(self.pending_transactions) != 0:
            transaction = self.pending_transactions.pop()
            if True: # itt validálni kellene az adott tranzakciót, a nem érvényeseket eldobja, de nem áll le
                validated_pending_transactions.append(transaction)
        self.pending_transactions = validated_pending_transactions
        return

    def find_unspent_outputs(self):
        self.unspent_outputs = []
        self.my_unspent_outputs = []
        for transaction in self.chain[0]['transactions']:
            self.unspent_outputs.append([transaction['txid'], 0, self.initial_csaposhi_offering])
            for output in transaction['outputs']:
                if output['recipient']==self.my_id:
                    self.my_unspent_outputs.append([transaction['txid'], 0, output['csaposhi']])
        for block in self.chain[1:]:
            for transaction in block['transactions']:
                for output in transaction['outputs']:
                    self.unspent_outputs.append([transaction['txid'], transaction['outputs'].index(output), output['csaposhi']])
                    if output['recipient'] == self.my_id:
                        self.my_unspent_outputs.append([transaction['txid'], transaction['outputs'].index(output), output['csaposhi']])
                for input in transaction['inputs']:
                    self.unspent_outputs.remove(input) # minden input biztosan szerepelt a lánc korábbi outputjaként
                    if input in self.my_unspent_outputs: # a remove() hibát dob, ha úgy törlünk a listából valamit, hogy nem is volt benne
                        self.my_unspent_outputs.remove(input)
        pprint(self.unspent_outputs)
        pprint(self.my_unspent_outputs)
        return

    def mine(self):
        if len(self.chain) == 0:
            previous_block_header_hash = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
        else:
            previous_block = self.chain[-1]
            previous_block_header = previous_block['block_header']
            previous_block_header_hash = self.create_hashhexvalue(previous_block_header)

        nonce = 0

        block_header = {
            'nonce': nonce,
            'previous_block_header_hash': previous_block_header_hash,
            'transactions_hash' : self.create_hashhexvalue(self.pending_transactions),
        }
        while True:
            block_header_hash = self.create_hashhexvalue(block_header)
            if block_header_hash[:4] == "0000":
                break
            block_header['nonce'] += 1

        block = {
            'block_header': block_header,
            'transactions': self.pending_transactions
        }
        pprint(block)

        self.chain.append(block)
        pprint (self.chain)
        self.save_list(self.chain, self.chain_filename)
        self.pending_transactions = []
        self.save_list(self.pending_transactions, self.pending_transactions_filename)
        return

    def generate_first_block(self):
        self.pending_transactions = []
        while len(self.ITKoin_users) > 0:
            recipient_id = self.load_id (self.ITKoin_users.pop()) # előveszi a következő id file nevét és beolvassa az id-t
            for tr in self.pending_transactions: # nem szerepelhet kétszer ugyanaz a recipient, mert akkor a txid azonos lesz
                for op in tr['outputs']:
                    if recipient_id == op['recipient']:
                        pprint ('HIBA: Ismétlődő recipient adatok az első blokk generálásakor.')
                        return False
            outputs = [{
                'csaposhi': self.initial_csaposhi_offering,
                'recipient': recipient_id}]
            transaction = {
                'inputs': [],
                'outputs': outputs}
            transaction ['txid'] = self.create_hashhexvalue(transaction) # a tranzakció lenyomata lesz az azonosítója egyben
            self.pending_transactions.append(transaction)
        pprint(self.pending_transactions)
        self.mine()
        return

    def new_transaction(self, csaposhi, recipient): # a megadott összeg átadása recipientnek, a maradék visszautalása
        sum = 0
        used_outputs=[]
        while (sum < csaposhi):
            next_output=self.my_unspent_outputs.pop()
            pprint(next_output)
            used_outputs.append(next_output)
            pprint(next_output)
            sum += next_output[2] # ebben a listapozícióban van a hivatkozott outputban kapott összeg
            pprint(sum)
        inputs = used_outputs
        pprint(inputs)
        for input in inputs: # az inputsban szándékosan nincs benne az akkori recipient, mert ezt abból a tranzakcióból kell kivenni és ellenőrizni
            input.append(self.create_signature(input[0])) # input[3] az aláírás érték base64 kódolással
            input.append(self.my_publickey.export_key().decode('ascii')) # input[4] a publikus kulcsom PEM formátumban
            pprint(self.verify_signature(input[0], input[3], RSA.import_key(input[4])))
        outputs = [{
            'csaposhi': csaposhi,
            'recipient': recipient}]
        if sum > csaposhi: # ha van visszajáró, azt visszautaljuk magunknak
            outputs.append({
                'csaposhi': sum-csaposhi,
                'recipient': self.my_id})
        transaction = {
            'inputs': inputs,
            'outputs': outputs}
        transaction ['txid'] = self.create_hashhexvalue(transaction) # a tranzakció lenyomata lesz az azonosítója egyben
        self.pending_transactions.append(transaction)
        pprint(self.pending_transactions)
        return



mycoin=ITKoin()
#mycoin.generate_rsa_key('csmkey_03')
#mycoin.generate_first_block()
#mycoin.load_my_private_key()
#mycoin.load_chain()
#mycoin.find_unspent_outputs()
#mycoin.new_transaction(20, 'c5425eda6099b4f481357fb12d17cda62e6f391ac49c83e9d465128dc47109b0')
#signature = mycoin.create_signature(2)
#pprint(signature)
#pprint(mycoin.my_publickey)
#print(mycoin.verify_signature(2, signature, mycoin.my_publickey))

#mycoin.mine()

