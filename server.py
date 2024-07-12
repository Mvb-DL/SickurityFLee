import socket, json, secrets
from model import get_model, get_second_model
import threading
from data import encode_layer, decode
from Crypto import Random
from Crypto.PublicKey import RSA
import hashlib, os, pickle, string
from Crypto.Cipher import PKCS1_OAEP
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import tensorflow as tf
from SmartContract.server_smart_contract import ServerSmartContract
import numpy as np
from data import get_data, get_second_data
import threading
from utils import decode_dict, encode_dict
from utils import ClientValidationContainer
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from sklearn.metrics import classification_report
import pandas as pd
from sklearn.model_selection import train_test_split
from commands.server_commands import commands
from OpenSSL import crypto
from sklearn.metrics import precision_score, recall_score, f1_score


def create_certificate(key, subject, issuer=None, ca_key=None):
    cert = crypto.X509()
    cert.get_subject().CN = subject
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10*365*24*60*60)
    cert.set_issuer(cert.get_subject() if issuer is None else issuer.get_subject())
    cert.set_pubkey(key)
    cert.sign(ca_key or key, 'sha256')
    return cert

def save_certificate(server_private_key, server_public_key, server_cert):

    with open("./certificates/aggregate_server_private_key.pem", "wb") as f:
        f.write(server_private_key)

    with open("./certificates/aggregate_server_public_key.pem", "wb") as f:
        f.write(server_public_key)

    with open("./certificates/aggregate_server_cert.pem", "wb") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, server_cert))


def load_certificate(cert_path):
    with open(cert_path, "rb") as f:
        cert_data = f.read()
    return crypto.load_certificate(crypto.FILETYPE_PEM, cert_data)

def load_public_key(key_path):
    with open(key_path, "rb") as f:
        key_data = f.read()
    return crypto.load_publickey(crypto.FILETYPE_PEM, key_data)

def validate_certificate(cert, public_key, server_socket):

    cert_public_key = cert.get_pubkey()
    
    cert_public_key_pem = crypto.dump_publickey(crypto.FILETYPE_PEM, cert_public_key)
    provided_public_key_pem = crypto.dump_publickey(crypto.FILETYPE_PEM, public_key)
    
    if cert_public_key_pem != provided_public_key_pem:
        raise ValueError("Public key does not match the certificate")
    
    store = crypto.X509Store()
    store.add_cert(cert)

    store_ctx = crypto.X509StoreContext(store, cert)
    
    try:
        store_ctx.verify_certificate()
        print("Certificate is valid and public key matches.")
        
    except crypto.X509StoreContextError as e:
        server_socket.close()
        raise ValueError(f"Certificate validation failed: {e}")

def print_certificate(cert):
    cert_text = crypto.dump_certificate(crypto.FILETYPE_TEXT, cert)
    print(cert_text.decode('utf-8'))


class Server:

    def __init__(self):
        
        #private and public keys
        random = Random.new().read
        RSAkey = RSA.generate(4096, random)
        self.public = RSAkey.publickey().exportKey()
        self.private = RSAkey.exportKey()

        server_key = crypto.load_privatekey(crypto.FILETYPE_PEM, self.private)
        server_cert = create_certificate(server_key, "Aggregate-Server")

        save_certificate(self.private, self.public, server_cert)

        tmpPub = hashlib.sha3_256(self.public)
        self.server_hash_public = tmpPub.hexdigest()

        #setting up aes
        self.AESKey = None
        self.delimiter_bytes = b'###'
        self.smart_contract_data = None
        self.smart_contract_abi = None
        self.smart_contract_address = None
        self.account_address = None

        self.eightByteClient = os.urandom(8)
        sess = hashlib.sha3_256(self.eightByteClient)
        self.session_client = sess.hexdigest()
        self.AESKeyClient = bytes(self.eightByteClient + self.eightByteClient[::-1])
        
        self.host = '127.0.0.1'
        self.port = 12345         
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket_client = None

        self.gateway_host = '127.0.0.1'
        self.gateway_port = 1234    

        #connected clients get append to list
        self.connected_nodes = list()
        self.connected_clients = set()
        self.pending_nodes = list()
        self.average_weights = {}

        self.required_nodes = 2
        self.max_rounds = 5
        self.clients_per_round = 0
        
        self.check = False
        self.training_round = 0
        self.epochs = 1

        #model which gets send to the client
        self.base_global_model = None
        self.global_model = None
        self.enc_global_model = None
        self.training_complete = threading.Event()
        self.server_model_test_data = None

        self.model_weights_list = []

        #set up to encrypt global model
        self.server_model_encode_key = None
        self.server_model_decode_key = None
        self.encrypted_model_hash_dict_client = {}

        self.gateway_public_key = None
        self.hashed_global_model = None
        self.server_smart_contract = None
        self.hashed_server_model_data = None

        #url gets saved in BC, that Client is getting connected to the correct server
        self.connection_url = self.host + ":" + str(self.port)

        self.server_reconnection_id = ""
        self.model_weights_updated = False
        self.average_client_model_weights = None
        self.model_input_lengths_from_server = None

        self.server_precision_history = []
        self.server_class_1_precision_history = []
        self.server_class_9_precision_history = []

        self.model_results = [None, None]

        self.base_smart_contract = None
        self.aggregate_server_smart_contract = None

        self.client_deviation_list = []

    def get_command_value(self, command_key):
        return commands.get(command_key)


    #build first gateway connection
    def build_gateway_connection(self):

        self.server_socket.connect((self.gateway_host, self.gateway_port))

        print(f"Verbindung zum Gateway-Server {self.gateway_host}:{self.gateway_port} hergestellt")

        gateway_open_thread = self.server_socket.recv(1024)

        if gateway_open_thread == self.get_command_value("command25"):

            self.server_socket.send(self.get_command_value("command26"))

            gateway_ready = self.server_socket.recv(1024)

            if gateway_ready == self.get_command_value("command27"):

                self.send_rsa_keys()

    
    def send_rsa_keys(self):

        self.server_socket.send(self.public + self.delimiter_bytes + self.server_hash_public.encode('utf-8'))

        self.get_gateway_respond()


    def set_aes_encryption(self, received_aes_data):

            splitServerSessionKey = received_aes_data.split(self.delimiter_bytes)

            fSendEnc = splitServerSessionKey[0]

            serverPublic = splitServerSessionKey[1]

            #encode data with private key
            private_key = RSA.import_key(self.private)
            cipher = PKCS1_OAEP.new(private_key)
            fSend = cipher.decrypt(fSendEnc)

            #eightbyte is the shared secret
            splittedDecrypt = fSend.split(self.delimiter_bytes)
            eightByte = splittedDecrypt[0]
            hashOfEight = splittedDecrypt[1].decode("utf-8")

            sess = hashlib.sha3_256(eightByte)
            session = sess.hexdigest()

            server_public_key = hashlib.sha3_256(serverPublic)
            server_public_hash = server_public_key.hexdigest()

            return hashOfEight, session, eightByte
    

    def aes_server_encoding(self, data):

        iv = os.urandom(16)

        # Create AES cipher object in CFB mode
        cipher = Cipher(algorithms.AES(self.AESKey), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # Encrypt the data
        encrypted_data = encryptor.update(data) + encryptor.finalize()

        # Return IV concatenated with encrypted data
        return iv + encrypted_data

    
    def aes_server_decoding(self, data):

        iv = data[:16]

        # Create AES cipher object in CFB mode
        cipher = Cipher(algorithms.AES(self.AESKey), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        # Decrypt the data
        decrypted_aes_data = decryptor.update(data[16:]) + decryptor.finalize()

        return decrypted_aes_data
    

    def verify_server_keys(self):
        
        serverPH = self.server_socket.recv(4096)

        split = serverPH.split(self.delimiter_bytes)

        ServerPublicKey = split[0].decode('utf-8')
        serverPublicKeyHash = split[1].decode('utf-8')

        cleanedServerPublicKey = ServerPublicKey.replace("\r\n", '')
        cleanedServerPublicKeyHash = serverPublicKeyHash.replace("\r\n", '')

        tmpServerPublic_bytes = cleanedServerPublicKey.encode('utf-8')

        tmpHashObject = hashlib.sha3_256(tmpServerPublic_bytes)
        tmpHash = tmpHashObject.hexdigest()

        return tmpHash, cleanedServerPublicKeyHash, ServerPublicKey


    def get_gateway_respond(self):
        
        tmpHash, GatewayPublicKeyHash, GatewayPublicKey = self.verify_server_keys()

        cert_path = "./certificates/gateway_server_cert.pem"
        public_key_path = "./certificates/gateway_server_public_key.pem"

        certificate = load_certificate(cert_path)
        public_key = load_public_key(public_key_path)

        validate_certificate(certificate, public_key, self.server_socket)

        if tmpHash == GatewayPublicKeyHash:

            print_certificate(certificate)

            self.gateway_public_key = GatewayPublicKey

            self.server_socket.send("GATEWAY_KEYS_VERIFIED_BY_SERVER".encode('utf-8'))

            #set up AES with Gateway
            received_aes_data = self.server_socket.recv(2048)

            hashOfEight, session, eightByte = self.set_aes_encryption(received_aes_data)

            if hashOfEight  == session: 

                self.AESKey = bytes(eightByte + eightByte[::-1])

                #sends back shared secret if it´s correct
                public_key = RSA.import_key(GatewayPublicKey)
                cipher = PKCS1_OAEP.new(public_key)
                encrypted_data = cipher.encrypt(eightByte)

                self.server_socket.send(encrypted_data)

                gateway_aes_msg = self.server_socket.recv(2048)
                decrypted_aes_data = self.aes_server_decoding(gateway_aes_msg)

                if decrypted_aes_data == self.get_command_value("command1"):
                    
                        aes_verified = self.aes_server_encoding(self.get_command_value("command2"))
                        self.server_socket.send(aes_verified)

                        get_connection_url = self.server_socket.recv(4096)
                        get_connection_url = self.aes_server_decoding(get_connection_url)

                        if self.get_command_value("command3") == get_connection_url:

                            #sending url of server to save in BC
                            connection_url = self.aes_server_encoding(self.connection_url.encode("utf-8"))
                            self.server_socket.send(connection_url)

                            gateway_respond = self.server_socket.recv(4096)
                            gateway_respond = self.aes_server_decoding(gateway_respond)

                            if gateway_respond == b"SERVER_ACCEPTED_FROM_GATEWAY":
                                
                                read_smart_contract = self.aes_server_encoding(self.get_command_value("command4"))
                                self.server_socket.send(read_smart_contract)

                                #aggregate-server gets smart contract
                                smart_contract_data_bytes = self.server_socket.recv(4096)
                                smart_contract_data = self.aes_server_decoding(smart_contract_data_bytes)
                                self.smart_contract_data = pickle.loads(smart_contract_data)
                                
                                print("***********************************************************")
                                print("")
                                print("Server Smart Contract: ", self.smart_contract_data)
                                print("")
                                print("***********************************************************")

                                read_smart_contract = self.aes_server_encoding(self.get_command_value("command5"))
                                self.server_socket.send(read_smart_contract)
                                
                                #save account adress to handle bc actions later on
                                self.account_address = self.smart_contract_data["AccountAddress"]

                                #server gets reconnection ID
                                server_reconnection_id = self.server_socket.recv(4096)
                                server_reconnection_id = self.aes_server_decoding(server_reconnection_id)
                                
                                self.server_reconnection_id = server_reconnection_id.decode("utf-8")

                                self.set_up_model()

        else:
            print("No Gateway Respond")    


    def train_pre_build_server_model(self, server_model_data):

        server_model_data = pickle.loads(server_model_data)

        #model weights gets overwritten to cut the length
        server_X_train = server_model_data["X_train"]
        server_y_train = server_model_data["y_train"]
        server_X_test = server_model_data["X_test"]
        server_y_test = server_model_data["y_test"]
        
        self.base_global_model.compile(optimizer='adam', loss=tf.keras.losses.CategoricalCrossentropy(from_logits=True), metrics=['accuracy'])
        self.base_global_model.fit(server_X_train, server_y_train, batch_size=16, epochs=self.epochs, validation_data=(server_X_test, server_y_test))

        y_pred_logits = self.base_global_model.predict(server_X_test)
        y_pred = np.argmax(y_pred_logits, axis=1)
        y_test_labels = np.argmax(server_y_test, axis=1)

        server_class_report = classification_report(y_test_labels, y_pred, target_names=[str(i) for i in range(10)], output_dict=True, zero_division=0)
        server_class_report = pd.DataFrame(server_class_report).transpose()
        
        server_test_loss, server_test_accuracy = self.base_global_model.evaluate(server_X_test, server_y_test)
        
        return server_test_loss, server_test_accuracy, server_class_report


    #the server builds by it´s own a model to have something to compare to the results of the clients
    def build_pre_trained_server_model(self):

        #the server loads his own independent data to compare it with the other clients
        self.X_train, self.y_train, self.X_test, self.y_test = get_second_data()

        X_train_sample, _, y_train_sample, _ = train_test_split(self.X_train, self.y_train, test_size=0.9, random_state=36)
        X_test_sample, _, y_test_sample, _ = train_test_split(self.X_test, self.y_test, test_size=0.9, random_state=36)   

        #data of server to test the client later on with PCA
        server_model_test_data = {
            "X_train": X_train_sample,
            "y_train": y_train_sample,
            "X_test": X_test_sample,
            "y_test": y_test_sample
        }

        server_model_test_data = pickle.dumps(server_model_test_data)

        return server_model_test_data


    #after getting smart contract server is setting up the model
    def set_up_model(self):

        #init the model
        base_global_model = get_second_model()
        self.base_global_model = base_global_model

        server_model_data = {
                "model_architecture": base_global_model.to_json(),
                "model_weights": encode_layer(base_global_model.get_weights()),
            }
        
        self.hashed_server_model_data = self.hash_model(server_model_data).hexdigest()
        
        server_model_data_json = json.dumps(server_model_data)
        self.global_model = pickle.dumps(server_model_data_json)

        #model gets hashed
        hashed_global_model = self.hash_model(self.global_model)
        self.hashed_global_model = hashed_global_model.hexdigest()

        #set up keys to encrypt and decrypt model and hash
        #model gets encrypted by ServerModelEncodeKey

        client_salt, client_iv, client_encryptor_tag, client_encrypted_data, self.server_model_decode_key = self.encrypt_global_model(self.global_model)

        encrypted_model_hash_dict_client = {
            "salt": client_salt,
            "iv": client_iv,
            "encryptor_tag": client_encryptor_tag,
            "encrypted_data": client_encrypted_data
        }

        self.encrypted_model_hash_dict_client = pickle.dumps(encrypted_model_hash_dict_client)

        #encrypted Model and Hash of unencrypted Model
        enc_model_data_dict = {'EncryptedModel': f'{self.enc_global_model}',
                                'ModelHash': f'{self.hashed_global_model}'}
        
        enc_model_data_bytes = encode_dict(enc_model_data_dict)
        
        #encrypted model and hash get encrypted by random key Enc(EncModel + Hash)
        gateway_salt, gateway_iv, gateway_encryptor_tag, gateway_encrypted_data, gateway_decrypt_dict_key = self.encrypt_final_global_model_hash_dict(enc_model_data_bytes)

        encrypted_model_hash_dict_gateway = {
            "salt": gateway_salt,
            "iv": gateway_iv,
            "encryptor_tag": gateway_encryptor_tag,
            "encrypted_data": gateway_encrypted_data
        }

        encrypted_model_hash_dict_gateway = pickle.dumps(encrypted_model_hash_dict_gateway)

        #this random key gets encrypted by PK from gateway server
        pk_enc_encrypt_key = self.encrypt_decrypt_dict_key(gateway_decrypt_dict_key)

        #encrypted model and hash get send to gateway
        pk_enc_encrypt_key = self.aes_server_encoding(pk_enc_encrypt_key)
        self.server_socket.send(pk_enc_encrypt_key)

        gateway_got_enc_encryption_key = self.server_socket.recv(1024)
        gateway_got_enc_encryption_key = self.aes_server_decoding(gateway_got_enc_encryption_key)

        if gateway_got_enc_encryption_key == self.get_command_value("command6"):

            encrypted_model_hash_dict = self.aes_server_encoding(encrypted_model_hash_dict_gateway )
            self.server_socket.sendall(encrypted_model_hash_dict)
            
            print("Sending enc model dict to gateway...")
            
            gateway_got_enc_model = self.server_socket.recv(1024)
            gateway_got_enc_model = self.aes_server_decoding(gateway_got_enc_model)

            if gateway_got_enc_model == self.get_command_value("command7"):
                    
                    get_smart_contract = self.aes_server_encoding(self.get_command_value("command8"))
                    self.server_socket.send(get_smart_contract)

                    #getting base smart contract
                    enc_serialized_base_smart_contract = self.server_socket.recv(32768)
                    serialized_base_smart_contract = self.aes_server_decoding(enc_serialized_base_smart_contract)
                    gateway_smart_contract_dict = pickle.loads(serialized_base_smart_contract)

                    self.gateway_smart_contract = ServerSmartContract().rebuild_smart_contract(gateway_smart_contract_dict)

                    print("Gateway Smart Contract Set Up!")

                    received_smart_contract = self.aes_server_encoding(self.get_command_value("command9"))
                    self.server_socket.send(received_smart_contract)

                    #hash the enc model
                    encrypted_model_hash = self.hash_model(self.enc_global_model)

                    print("Final Account Address", self.account_address)

                    server_model_set_up = ServerSmartContract().set_up_global_model(
                                                                                encrypted_model_hash.hexdigest(),
                                                                                self.hashed_global_model,
                                                                                self.account_address,
                                                                                self.gateway_smart_contract
                                                                                )
                    
                    if server_model_set_up:

                        updated_server_smart_contract = ServerSmartContract().get_aggregate_server(
                                                                            self.account_address,
                                                                            self.gateway_smart_contract
                                                                        )

                        print("***********************************************************")
                        print("")
                        print("Updated Server Smart Contract: ", updated_server_smart_contract)
                        print("")
                        print("***********************************************************")

                        self.run_server()


    #hash the model
    def hash_model(self, global_model):
        
        hashed_global_model = hashlib.sha3_256(str(global_model).encode('utf-8'))
        return hashed_global_model
    

    #encrypt globale model with server model encode key
    def encrypt_global_model(self, global_model):
    
            password = self.generate_random_string(16)
            
            salt = os.urandom(16)

            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )

            key = kdf.derive(password.encode())

            # Generate a random initialization vector
            iv = os.urandom(12)

            cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
            encryptor = cipher.encryptor()

            padder = padding.PKCS7(algorithms.AES.block_size).padder()
            padded_data = padder.update(global_model) + padder.finalize()

            # Encrypt the data
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

            server_model_decode_key = password.encode()

            return salt, iv, encryptor.tag, encrypted_data, server_model_decode_key


    def generate_random_string(self, length):
        alphabet = string.ascii_letters + string.digits + string.punctuation
        random_string = ''.join(secrets.choice(alphabet) for _ in range(length))
        return random_string
    
    
    #encrypt the model and it´s hash with a random generated key
    def encrypt_final_global_model_hash_dict(self, enc_model_data):
            
            password = self.generate_random_string(16)
            
            salt = os.urandom(16)

            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )

            key = kdf.derive(password.encode())

            # Generate a random initialization vector
            iv = os.urandom(12)

            cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
            encryptor = cipher.encryptor()

            padder = padding.PKCS7(algorithms.AES.block_size).padder()
            padded_data = padder.update(enc_model_data) + padder.finalize()

            # Encrypt the data
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

            encrypt_dict_key = password.encode()

            return salt, iv, encryptor.tag, encrypted_data, encrypt_dict_key


    def encrypt_decrypt_dict_key(self, encrypt_key):

        #encrypt key, which encryptes Model and Hash with GatewayPublicKey
        key = RSA.importKey(self.gateway_public_key)
        cipher = PKCS1_OAEP.new(key)
        pk_enc_encrypt_key = cipher.encrypt(encrypt_key)

        return pk_enc_encrypt_key


    def test_gateway_connection(self, client_socket):

        random_bytes = os.urandom(10)
        random_bytes_hash = self.hash_model(random_bytes)
        random_bytes_hash = random_bytes_hash.hexdigest()

        print("Server Connection Test Hash", random_bytes_hash)

        random_test_byte_sequence = self.aes_server_encoding(random_bytes)
        client_socket.send(random_test_byte_sequence)

        server_test_byte_response = client_socket.recv(2048)
        server_test_byte_response = self.aes_server_decoding(server_test_byte_response)

        if str(random_bytes_hash) == str(server_test_byte_response.decode("utf-8")):

            print("Gateway is successfully reconnected with Server...")

            server_waiting_model_weights = self.aes_server_encoding(self.get_command_value("command10"))
            client_socket.send(server_waiting_model_weights)

            #getting the model weights from the gateway server
            self.get_client_model_weights(client_socket)


    # sever is getting the model weights from the client via the gateway server
    def get_client_model_weights(self, client_socket):

            enc_client_model_weights = client_socket.recv(1048576)
            enc_client_model_weights = self.aes_server_decoding(enc_client_model_weights)

            server_model_weights_list = []
            
            #liste mit dicts
            final_client_model_weights = pickle.loads(enc_client_model_weights)

            for client_dictionary in list(final_client_model_weights):

                client_dictionary = pickle.loads(client_dictionary)

                client_device_key = client_dictionary["DeviceKey"]
                client_model_weights = client_dictionary["ModelWeights"]


                if self.verify_client_model_weights(client_device_key, client_model_weights, client_socket) is False:

                    print(f"Model weights of Client Device Key: {client_device_key} not correct")
                    client_socket.close()

                else:
                    server_model_weights_list.append(client_model_weights)
                    print("Client Device Key", client_device_key)
            

            #save final_client_model_weights
            self.aggregate_client_model_weights(server_model_weights_list, client_socket)


    #send model weights back to gateway
    def send_updated_model_weights(self, client_socket):
        
        server_model_weights = {
            "ServerAccountAddress": f"{self.account_address}",
            "ServerModelWeights": self.average_client_model_weights
        }

        average_client_model_weights = pickle.dumps(server_model_weights)
        updated_client_model_weights = self.aes_server_encoding(average_client_model_weights)
        client_socket.send(updated_client_model_weights)

        received_gateway_model_weights = client_socket.recv(2048)
        received_gateway_model_weights = self.aes_server_decoding(received_gateway_model_weights)

        if received_gateway_model_weights == self.get_command_value("command11"):

            #if sending sucessfull, when model weights were not changed!
            self.average_client_model_weights = None

            #ending round of training
            self.training_round +=1

            print()
            print("Max Rounds of Training: ", self.max_rounds, "Round Number: ", int(self.training_round))
            print()

            if int(self.max_rounds) <= int(self.training_round):
                
                server_waiting_model_weights = self.aes_server_encoding(self.get_command_value("command12"))
                client_socket.send(server_waiting_model_weights)

                print("All Rounds were finished successfully...")
                self.close_connection()

            else:

                server_waiting_model_weights = self.aes_server_encoding(self.get_command_value("command13"))
                client_socket.send(server_waiting_model_weights)

                #close old connection
                self.close_connection()

                #reopen the server again for connections
                self.run_server()


    #checks if client really exists in BC and if model weights has changed on Serverside
    def verify_client_model_weights(self, client_device_key, client_model_weights, client_socket):
        
        client_smart_contract_model_weights= ServerSmartContract().get_client_model_weights_server(client_device_key,
                                                                                        self.account_address,
                                                                                        self.gateway_smart_contract)

        hashed_client_model_weights = self.hash_model(client_model_weights)

        if str(client_smart_contract_model_weights["ModelWeightsHash"]) == str(hashed_client_model_weights.hexdigest()):

            print()
            print("Server Verification. Modelweights were not changed")
            print()
            print("Client Smart Contract: ", client_smart_contract_model_weights)
            print()

            return True

        else:
            print("Modell Weights of client were changed!")
            client_socket.close()
            return False
    

    #Krum Alternative 1
    def squared_distance(self, grad1, grad2):

        return np.sum((grad1 - grad2) ** 2)
    
    def krum_alternative(self, client_model_weights_list, nbworkers, nbbyzwrks):

        nbselected = nbworkers - nbbyzwrks - 2
        scores = []

        for i in range(nbworkers):
            distances = []
            for j in range(nbworkers):
                if i != j:
                    distance = self.squared_distance(
                        np.concatenate([client_model_weights_list[i][k].flatten() for k in range(len(client_model_weights_list[0]))]),
                        np.concatenate([client_model_weights_list[j][k].flatten() for k in range(len(client_model_weights_list[0]))])
                    )
                    distances.append(distance)
            distances.sort()
            score = sum(distances[:nbselected])
            scores.append((score, client_model_weights_list[i]))

        scores.sort(key=lambda x: x[0])
        return scores[0][1]  
    

    def aggregate_layerwise(self, client_model_weights_list, nbworkers, nbbyzwrks):

        num_layers = len(client_model_weights_list[0])
        aggregated_weights = []

        for layer in range(num_layers):
            layer_weights = [client[layer] for client in client_model_weights_list]
            krum_result = self.krum_alternative(layer_weights, nbworkers, nbbyzwrks)
            aggregated_weights.append(krum_result)

        return aggregated_weights


    #Krum Alternative 2
    def krum(self, client_model_weights_list, num_byzantine):

        num_clients = len(client_model_weights_list)
        scores = []

        for i in range(num_clients):
            distances = []
            for j in range(num_clients):
                if i != j:
                    distances.append(np.linalg.norm(np.concatenate([client_model_weights_list[i][k].flatten() - client_model_weights_list[j][k].flatten() for k in range(len(client_model_weights_list[0]))])))
            distances.sort()

            scores.append(sum(distances[:num_clients - num_byzantine - 2]))

        krum_index = np.argmin(scores)

        return client_model_weights_list[krum_index]
    

    #clipping client weight defense mechanism one
    def clipping_client_weights(self, client_model_weights_list):
        
        def clip_weights(weights, clip_value=1.0):
            clipped_weights = [np.clip(weight, -clip_value, clip_value) for weight in weights]
            return clipped_weights
        
        def detect_anomalies(client_weights, threshold=2.0):

            flattened_weights = [np.concatenate([w.flatten() for w in weights]) for weights in client_weights]

            mean_weights = np.mean(flattened_weights, axis=0)
            std_weights = np.std(flattened_weights, axis=0)

            anomalies = []

            for i, weights in enumerate(flattened_weights):
                if np.any(np.abs(weights - mean_weights) > threshold * std_weights):
                    anomalies.append(i)
            return anomalies

        
        clipped_client_weights = [clip_weights(weights) for weights in client_model_weights_list]
        
        anomalies = detect_anomalies(clipped_client_weights)
        filtered_client_weights = [weights for i, weights in enumerate(clipped_client_weights) if i not in anomalies]

        return filtered_client_weights
    
    #normal FedAvg
    def fedAvg(self, client_model_weights_list):

        average_client_model_weights = [
               np.mean([weights[i] for weights in client_model_weights_list], axis=0)
                for i in range(len(client_model_weights_list[0]))
        ]

        return average_client_model_weights


    #loads the model weights from the database and aggregate them
    def aggregate_client_model_weights(self, client_model_weights_list, client_socket):

        average_client_model_weights = []
        num_byzantine = 1

        print(f"Collected: {len(client_model_weights_list)} client Weights")

        #clipping Model weights
        #client_model_weights_list = self.clipping_client_weights(client_model_weights_list)

        #krum alternative
        average_client_model_weights = self.krum(client_model_weights_list, num_byzantine)

        #normal FedAvg
        #average_client_model_weights = self.fedAvg(client_model_weights_list)

        self.set_aggregated_model_weights(average_client_model_weights, client_socket)


    #update model weights in BC
    def set_aggregated_model_weights(self, average_client_model_weights, client_socket):

        average_client_model_weights_hash = self.hash_model(average_client_model_weights)
        average_client_model_weights_hash = average_client_model_weights_hash.hexdigest()

        smart_contract_global_model_weights = ServerSmartContract().set_aggregated_model_weights(
                                                                                    average_client_model_weights_hash,
                                                                                    self.account_address,
                                                                                    self.gateway_smart_contract)
        
        #return updated model weights to gateway
        self.average_client_model_weights = average_client_model_weights

        if self.test_aggregate_server_model(self.average_client_model_weights):

            self.send_updated_model_weights(client_socket)

        else:
            print("Server detected anomalies after aggregation...")


    #server tests model after aggregation
    def test_aggregate_server_model(self, average_client_model_weights):

        def get_metrics_per_class(X_test, y_test):
            
            y_pred = np.argmax(self.base_global_model.predict(X_test), axis=1)
            y_true = np.argmax(y_test, axis=1)
            precision_per_class = precision_score(y_true, y_pred, average=None, zero_division=0)
            recall_per_class = recall_score(y_true, y_pred, average=None)
            f1_per_class = f1_score(y_true, y_pred, average=None)

            return precision_per_class, recall_per_class, f1_per_class

        if self.server_model_test_data is not None:

            #set aggregated model weights
            self.base_global_model.set_weights(average_client_model_weights)
            self.base_global_model.summary()

            server_X_train, server_y_train, server_X_test, server_y_test = get_second_data()
            server_X_train, _, server_y_train, _ = train_test_split(server_X_train, server_y_train, random_state=24)
            server_X_test, _, server_y_test, _ = train_test_split(server_X_test, server_y_test, random_state=24)  

            self.base_global_model.compile(optimizer='adam', loss=tf.keras.losses.CategoricalCrossentropy(from_logits=True), metrics=['accuracy'])
            server_test_loss, server_test_accuracy = self.base_global_model.evaluate(server_X_test, server_y_test)

            precision_per_class, recall_per_class, f1_per_class = get_metrics_per_class(server_X_test, server_y_test)

            self.server_precision_history.append(server_test_accuracy)
            self.server_class_1_precision_history.append(precision_per_class[1])
            self.server_class_9_precision_history.append(precision_per_class[9])

            print()
            print("Server Accuracy: ", server_test_accuracy)
            print()
            print("Server Test Loss: ", server_test_loss)
            print()
            print("Precision per Class: ", precision_per_class)
            print()
            print("Recall per Class: ", recall_per_class)
            print()
            print("F1-Score per Class: ", f1_per_class)
            print()
            print(f"Server Precision History: {self.server_precision_history}. Mean Value: {sum(self.server_precision_history) / len(self.server_precision_history)}")
            print()
            print(f"Server Precision Class 1 History: {self.server_class_1_precision_history}. Mean Value: {sum(self.server_class_1_precision_history) / len(self.server_class_1_precision_history)}")
            print()
            print(f"Server Precision Class 9 History: {self.server_class_9_precision_history}. Mean Value: {sum(self.server_class_9_precision_history) / len(self.server_class_9_precision_history)}")
            print()

            return True
        
        else:
            print("Server Data is none!")
        
    
############### Client Section ####################

    #starts the server to get connected with clients
    def run_server(self):

        self.server_socket_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket_client.bind((self.host, self.port))
        self.server_socket_client.listen()
        print()
        print(f"Server auf {self.host}:{self.port}")
        print()

        self.get_client_request()
    

    #get request from client
    def get_client_request(self):

        try:

                client_socket, client_address = self.server_socket_client.accept()
                
                print(f"Verbindung von {client_address}")

                #checks if gateway or client is connecting
                connection_request = client_socket.recv(2048)

                if connection_request != self.get_command_value("command14"):

                    #checks if gateway will reconnect
                    if connection_request == self.get_command_value("command15"):

                        self.test_gateway_connection(client_socket)

                else:

                    client_socket.send(self.get_command_value("command16"))

                    tmpHash, clientPublicHash, ClientPublicKey = self.verify_client_keys(client_socket)

                    if str(tmpHash) == str(clientPublicHash):
                
                        self.build_client_threats(client_socket, ClientPublicKey, client_address)
            
        except KeyboardInterrupt:
            print("Server wurde beendet.")

    
    def build_client_threats(self, client_socket, client_public_key, client_address):

            # Client zur Client-Liste hinzufügen
            self.connected_clients.add(client_socket)
            self.connected_nodes.append(client_address)

            # Mehrere Clients handhaben
            client_thread = threading.Thread(target=self.send_server_keys, args=(client_socket, client_address, client_public_key, ))
            client_thread.start()
    


    #client sends its public key and it´s hashed. Here it gets checked
    def verify_client_keys(self, client_socket):
        
        clientPH = client_socket.recv(4096)
        split = clientPH.split(self.delimiter_bytes)

        ClientPublicKey = split[0].decode('utf-8')
        clientPublicKeyHash = split[1].decode('utf-8')

        cleanedClientPublicKey = ClientPublicKey.replace("\r\n", '')
        cleanedClientPublicKeyHash = clientPublicKeyHash.replace("\r\n", '')

        tmpClientPublic_bytes = cleanedClientPublicKey.encode('utf-8')

        tmpHashObject = hashlib.sha3_256(tmpClientPublic_bytes)
        tmpHash = tmpHashObject.hexdigest()

        return tmpHash, cleanedClientPublicKeyHash, ClientPublicKey
    

    #set up aes encryption for communication    
    def build_server_client_aes_encryption(self, client_public_key):

        session_bytes = self.session_client.encode('utf-8')

        #encode with publickey from client
        key = RSA.importKey(client_public_key)
        cipher = PKCS1_OAEP.new(key)
        fSend = self.eightByteClient + self.delimiter_bytes + session_bytes
        fSendEnc = cipher.encrypt(fSend)

        return fSendEnc
    
    
    #encode aes messages for client
    def aes_client_encoding(self, data):

        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.AESKeyClient), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(data) + encryptor.finalize()

        return iv + encrypted_data


    #decode aes messages from client
    def aes_client_decoding(self, data):

        iv = data[:16]
        cipher = Cipher(algorithms.AES(self.AESKeyClient), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_aes_data = decryptor.update(data[16:]) + decryptor.finalize()

        return decrypted_aes_data
    

    #sending server keys to client
    def send_server_keys(self,  client_socket, client_address, ClientPublicKey):

        #after receiving client keys, server sends its keys back
        client_socket.send(self.public + self.delimiter_bytes + self.server_hash_public.encode('utf-8'))

        self.get_participant_data(client_socket, client_address, ClientPublicKey)

    
    def get_participant_data(self, client_socket, client_address, client_public_key):

        client_ack_server_keys = client_socket.recv(1024)

        #wait for response before building session keys
        if client_ack_server_keys == self.get_command_value("command17"):

            #after exchanging rsa keys, build up aes encryption
            fSendEnc = self.build_server_client_aes_encryption(client_public_key)
            client_socket.send(bytes(fSendEnc + self.delimiter_bytes + self.public))

            clientPH = client_socket.recv(4096)

            if len(clientPH) > 0:

                private_key = RSA.import_key(self.private)
                cipher = PKCS1_OAEP.new(private_key)
                decrypted_data_client = cipher.decrypt(clientPH)

                if decrypted_data_client == self.eightByteClient:

                    encrypted_data = self.aes_client_encoding(self.get_command_value("command18"))
                    client_socket.send(encrypted_data)

                    client_aes_ready = client_socket.recv(4096)
                    client_aes_ready = self.aes_client_decoding(client_aes_ready)

                    #client and server are now ready for fully aes encryption
                    if client_aes_ready == self.get_command_value("command19"):

                        print("Client and Server are ready for fully aes encryption")

                        wait_client_smart_contract = self.aes_client_encoding(self.get_command_value("command20"))
                        client_socket.send(wait_client_smart_contract)

                        client_smart_contract = client_socket.recv(4096)
                        client_smart_contract = self.aes_client_decoding(client_smart_contract)
                        client_smart_contract = pickle.loads(client_smart_contract)

                        #server checks if client is in BC from gateway contract
                        server_smart_contract_data = ServerSmartContract().get_client_by_public_key(client_smart_contract["AccountId"],
                                                                                                    self.gateway_smart_contract)

                        if bool(server_smart_contract_data) == True:
                            
                            wait_enc_model_and_id = self.aes_client_encoding(self.get_command_value("command21"))
                            client_socket.send(wait_enc_model_and_id)

                            client_waiting_enc_dict = client_socket.recv(4096)
                            client_waiting_enc_dict  = self.aes_client_decoding(client_waiting_enc_dict )

                            if client_waiting_enc_dict == b"CLIENT_WAITING_FOR_MODEL_ENCRYPTION":

                                enc_encrypted_model_hash_dict_client = self.aes_client_encoding(self.encrypted_model_hash_dict_client)
                                client_socket.send(enc_encrypted_model_hash_dict_client)

                            else:

                                print("Server Model not possible to encrypt")
                            
                            enc_client_model_hash = client_socket.recv(4096)
                            enc_client_model_hash = self.aes_client_decoding(enc_client_model_hash)
                            enc_client_model_hash = enc_client_model_hash.decode("utf-8")

                            #checks if model which the client received is the same as send before                            
                            enc = self.hash_model(self.enc_global_model)

                            #if model is verified than ServerModelDecodeKey gets sended
                            if str(enc.hexdigest()) == str(enc_client_model_hash):

                                server_model_decode_key = self.aes_client_encoding(self.server_model_decode_key)
                                client_socket.send(server_model_decode_key)

                                final_model_verification = client_socket.recv(1024)
                                final_model_verification = self.aes_client_decoding(final_model_verification)

                                if final_model_verification == self.get_command_value("command22"):
                                    
                                    #Data Length Params
                                    #set up the server data to train it´s own model
                                    server_model_test_data = self.build_pre_trained_server_model()
                                    self.server_model_test_data = server_model_test_data

                                    waiting_client_data_hash = self.aes_client_encoding(self.get_command_value("command23"))
                                    client_socket.send(waiting_client_data_hash)

                                    #set up training validation container for client
                                    client_data_hash = client_socket.recv(1024)
                                    client_data_hash = self.aes_client_decoding(client_data_hash)

                                    #server fills up the blackbox
                                    client_container = ClientValidationContainer(self.hashed_server_model_data, client_data_hash,
                                                                                  server_model_test_data, self.public)
                                    
                                    pickled_client_container = pickle.dumps(client_container)

                                    pickled_client_container = self.aes_client_encoding(pickled_client_container)
                                    client_socket.sendall(pickled_client_container)

                                    #train the server model with its own data to compare it with the client
                                    server_test_loss, server_test_accuracy, server_class_report = self.train_pre_build_server_model(server_model_test_data)

                                    #receiving the loss and acc from client to compare with server loss and acc
                                    client_model_test_validation = client_socket.recv(16384)
                                    enc_client_model_test_validation = self.aes_client_decoding(client_model_test_validation)

                                    rsa_key = RSA.import_key(self.private)
                                    cipher_rsa = PKCS1_OAEP.new(rsa_key)
                                    chunk_size = rsa_key.size_in_bytes()
    
                                    encrypted_chunks = [enc_client_model_test_validation[i:i + chunk_size] for i in range(0, len(enc_client_model_test_validation), chunk_size)]
                                    decrypted_chunks = [cipher_rsa.decrypt(chunk) for chunk in encrypted_chunks]

                                    decrypted_message = b''.join(decrypted_chunks)                                    
                                    client_model_test_validation = pickle.loads(decrypted_message)

                                    #get results of client and test if its malicious
                                    if self.validate_client_model_performance(server_test_loss,
                                                                               server_test_accuracy,
                                                                               server_class_report,
                                                                               client_model_test_validation):
                                        

                                        print(f"Number connected Clients: {len(self.connected_nodes)}")

                                        for client in self.connected_clients:

                                                    print(client)

                                                    client_accessed = self.aes_client_encoding(self.get_command_value("command24"))
                                                    client.send(client_accessed)

                                        self.run_server()

                                       

                        else:
                            print("Client is not registered!")


    def validation_flags(self, flag_one, flag_two, flag_three):

        result_flag = (int(flag_one) + int(flag_two) + int(flag_three))

        if result_flag > 7:
            print("Most Highest Client Risk")
            return False
        
        if result_flag > 5 and result_flag < 7:
            print("Very High Client Risk")
            return False
        
        if result_flag > 2 and result_flag < 5:
            print("High Client Risk")
            return False
        
        if result_flag <= 2:
            print("Higher Client Risk")
            return True
        
        if result_flag < 2:
            print("Moderate Client Risk")
            return True


    def calc_precision_recall_deviation(self, client_test_accuracy, client_test_loss, server_test_accuracy, server_test_loss):

        accuracy_difference = abs(server_test_accuracy - client_test_accuracy)
        loss_difference = abs(server_test_loss - client_test_loss)

        accuracy_deviation_percent = (accuracy_difference * 100)
        loss_deviation_percent = (loss_difference * 100)

        if accuracy_deviation_percent > 4:
            flag_value = 3
            return flag_value
        
        elif accuracy_deviation_percent > 3:
            flag_value = 2
            return flag_value
        
        elif accuracy_deviation_percent > 2:
            flag_value = 1
            return flag_value
        
        else:
            flag_value = 0
            return flag_value

#!!!!!!
    def validate_client_model_performance(self, server_test_loss, server_test_accuracy, server_class_report, client_model_test_validation):

        flag_one = 0
        flag_two = 0
        flag_three = 0

        all_class_data = client_model_test_validation["AllClassData"]

        class_outliers = client_model_test_validation["ClassOutliers"]
        class_outliers = class_outliers["class"]
        class_outliers_list = list(class_outliers)
        class_outliers_list = [int(element) for element in class_outliers_list]

        client_class_report = pd.DataFrame(client_model_test_validation["ClassReport"])

        client_test_loss = client_model_test_validation["ClientTestLoss"]
        client_test_accuracy = client_model_test_validation["ClientTestAccuracy"]

        class_report_no_overall = client_class_report[:-3]

        lowest_precision_idx = class_report_no_overall['precision'].nsmallest(1).idxmax()
        lowest_precision_row = class_report_no_overall.loc[lowest_precision_idx]

        second_lowest_precision_idx = class_report_no_overall['precision'].nsmallest(2).idxmax()
        second_lowest_precision_row = class_report_no_overall.loc[second_lowest_precision_idx]

        if int(lowest_precision_idx) in class_outliers_list:

            lowest_result = pd.DataFrame({
                'class': [lowest_precision_idx],
                'precision': [lowest_precision_row['precision']],
                'recall': [lowest_precision_row['recall']]
            })

            print(lowest_result)
            flag_one = 3

        if int(second_lowest_precision_idx) in class_outliers_list:

            second_lowest_result = pd.DataFrame({
                'class': [second_lowest_precision_idx],
                'precision': [second_lowest_precision_row['precision']],
                'recall': [second_lowest_precision_row['recall']]
            })

            print(second_lowest_result)
            flag_two = 3

        flag_three = self.calc_precision_recall_deviation(client_test_accuracy, client_test_loss, server_test_accuracy, server_test_loss)

        print("*******************************************")
        print("Server vs. Client Data & Model Validation")
        print()
        print("Difference Server Data Classes and Client Data Classes")
        print(all_class_data)
        print()
        print("Client Model Performance")
        print(client_class_report)
        print()
        print("Server Model Performance")
        print(server_class_report)
        print()
        print("Client Precision: ", client_test_accuracy)
        print()
        print("Server Precision: ", server_test_accuracy)
        print()
        print("Client Loss: ", client_test_loss)
        print()
        print("Server Loss: ", server_test_loss)
        print("*******************************************")

#!!!!!!!!
        if self.validation_flags(flag_one, flag_two, flag_three):
            return True
        
        elif self.validation_flags(flag_one, flag_two, flag_three) is False:
            return True

    #The average test results of the clients are collected and if there is a large deviation, the client is rejected
    def model_deviation_approximation(self, client_deviation, server_test_accuracy):

        self.client_deviation_list.append(client_deviation)

        percent_deviations = [
            (abs(server_test_accuracy - accuracy) / server_test_accuracy) * 100
            for accuracy in self.client_deviation_list
        ]

        average_percent_deviation = sum(percent_deviations) / len(self.client_deviation_list)

        print("Average percent deviation: ", average_percent_deviation)


    #close server and client connection
    def close_connection(self):
        self.server_socket.close()
        print("Server Connection closed")
        for client_socket in self.connected_clients:
                client_socket.close()


if __name__ == "__main__":

    server = Server()
    server.build_gateway_connection()