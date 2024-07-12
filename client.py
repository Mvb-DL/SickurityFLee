import socket, json, os, random, time
from data import get_data, get_second_data, data_poisoning, data_poisoning_extrem
from tensorflow.keras.models import model_from_json
import tensorflow as tf
from data import decode
import tkinter as tk
from tkinter import * 
import customtkinter
from Crypto import Random
from Crypto.PublicKey import RSA
import hashlib, pickle
from Crypto.Cipher import PKCS1_OAEP
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from SmartContract.client_smart_contract import ClientSmartContract
from utils import decode_dict
import numpy as np
import secrets
from commands.client_commands import commands
from client_gui.ClientGui import RegistrationPage, GatewaySelectPage, ModelSelectPage, ValidationPage, TrainingPage
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from sklearn.metrics import classification_report
from OpenSSL import crypto
from sklearn.utils import shuffle


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

    with open("./certificates/client_private_key.pem", "wb") as f:
        f.write(server_private_key)

    with open("./certificates/client_public_key.pem", "wb") as f:
        f.write(server_public_key)

    with open("./certificates/client_cert.pem", "wb") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, server_cert))


def load_certificate(cert_path):
    with open(cert_path, "rb") as f:
        cert_data = f.read()
    return crypto.load_certificate(crypto.FILETYPE_PEM, cert_data)

def load_public_key(key_path):
    with open(key_path, "rb") as f:
        key_data = f.read()
    return crypto.load_publickey(crypto.FILETYPE_PEM, key_data)

def validate_certificate(cert, public_key, client_socket):

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
        client_socket.close()
        raise ValueError(f"Certificate validation failed: {e}")

def print_certificate(cert):
    cert_text = crypto.dump_certificate(crypto.FILETYPE_TEXT, cert)
    print(cert_text.decode('utf-8'))


class Client:

    def __init__(self, master):

        self.master = master

        #client ports for gateway to connect
        self.client_host = "127.0.0.1"
        self.client_port = secrets.randbelow(65535 - 49152 + 1) + 49152

        #private and public keys
        random = Random.new().read
        RSAkey = RSA.generate(4096, random)
        self.public = RSAkey.publickey().exportKey()
        self.private = RSAkey.exportKey()

        client_key = crypto.load_privatekey(crypto.FILETYPE_PEM, self.private)
        client_cert = create_certificate(client_key, "Client")

        save_certificate(self.private, self.public, client_cert)

        tmpPub = hashlib.sha3_256(self.public)
        self.client_hash_public = tmpPub.hexdigest()

        #setting up
        self.AESKey = None
        self.AESKeyServer = None

        self.delimiter_bytes = b'###'

        #build up gateway-server connection
        self.gateway_host = '127.0.0.1'
        self.gateway_port = 1234         

        #build up server connection
        self.host = '127.0.0.1'
        self.port = 12345         

        #GUI STUFF
        self.entry = tk.Entry(master)
        self.text = tk.Text(master)
        self.username_entry = tk.Entry(master)
        self.password_entry = tk.Entry(master, show="*")
        self.email_entry = tk.Entry(master)

        #trainingsdata of the client
        X_train, y_train, X_test, y_test = data_poisoning()
        self.X_train, self.y_train = shuffle(X_train, y_train, random_state=42)
        self.X_test, self.y_test = shuffle(X_test, y_test, random_state=42)

        self.model = None
        self.epochs = 5
        self.server_data = ""
        self.chunk_size = 4096
        self.batch_size = 16

        self.model_weights = dict()
        self.client_account_address = None
        self.client_device_key = None

        self.enc_model_hash = None
        self.enc_global_model = b''
        self.model_hash = None
        self.selected_server_connection_url = None

        self.client_server_socket = None
        self.client_socket = None

        self.client_reconnection_id = ""

        self.has_send_model_weights = False
        self.smart_contract_abi = None
        self.smart_contract_address = None

        self.gateway_smart_contract = None

        self.frames = {}

        self.client_reconnection_set = set()
        self.last_training_round = False

        def get_command_value(self, command_key):
            return commands.get(command_key)

        #wenn gateway mitrein
        self.entry_point()

    def entry_point(self):

        if self.build_gui(self.master):

            self.show_frame(GatewaySelectPage)

            if self.select_gateway():

                self.build_gateway_connection()

      
    #build first gateway connection
    def build_gateway_connection(self):

            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((self.gateway_host, self.gateway_port))

            print(f"Verbindung zum Gateway-Server {self.gateway_host}:{self.gateway_port} hergestellt")

            gateway_open_thread = self.client_socket.recv(1024)

            print(gateway_open_thread)

            if gateway_open_thread == b"OPEN_THREAD":

                self.client_socket.send(b"CLIENT_READY_FOR_RSA")

                gateway_ready = self.client_socket.recv(1024)

                if gateway_ready == b"GATEWAY_READY_FOR_RSA":

                    self.show_frame(RegistrationPage)


    def build_gui(self, master):

        container = tk.Frame(master)
        container.config(bg="black", width=1200, height=800)
        container.pack(expand = True)

        for F in (RegistrationPage, GatewaySelectPage, ModelSelectPage, ValidationPage, TrainingPage):

            frame = F(container, self)
            self.frames[F] = frame
            frame.grid(row=0, column=0, sticky="nsew")

        return True


    def show_frame(self, cont):
        frame = self.frames[cont]
        frame.tkraise()

    def server_gui(self):
        self.show_frame(TrainingPage)
        self.master.destroy()

    def select_gateway(self):
        return True
 
    def send_register_data(self):
        self.show_frame(ModelSelectPage)


    def select_ml_model(self):

        message = self.public + self.delimiter_bytes + self.client_hash_public.encode('utf-8')
        self.client_socket.send(message)   

        print("Start")
        
        self.show_frame(ValidationPage)
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
    
            
    #verifying gateway keys
    def verify_gateway_keys(self):
        
        serverPH = self.client_socket.recv(4096)
        split = serverPH.split(self.delimiter_bytes)

        ServerPublicKey = split[0].decode('utf-8')
        serverPublicKeyHash = split[1].decode('utf-8')

        cleanedServerPublicKey = ServerPublicKey.replace("\r\n", '')
        cleanedServerPublicKeyHash = serverPublicKeyHash.replace("\r\n", '')

        tmpServerPublic_bytes = cleanedServerPublicKey.encode('utf-8')

        tmpHashObject = hashlib.sha3_256(tmpServerPublic_bytes)
        tmpHash = tmpHashObject.hexdigest()

        return tmpHash, cleanedServerPublicKeyHash, ServerPublicKey
    
    
    def aes_client_decoding(self, data):

        iv = data[:16]
        cipher = Cipher(algorithms.AES(self.AESKey), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_aes_data = decryptor.update(data[16:]) + decryptor.finalize()

        return decrypted_aes_data
    

    def aes_client_encoding(self, data):

        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.AESKey), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(data) + encryptor.finalize()

        return iv + encrypted_data


    def get_gateway_respond(self):
        
        tmpHash, GatewayPublicKeyHash, GatewayPublicKey = self.verify_gateway_keys()

        cert_path = "./certificates/gateway_server_cert.pem"
        public_key_path = "./certificates/gateway_server_public_key.pem"

        certificate = load_certificate(cert_path)
        public_key = load_public_key(public_key_path)

        validate_certificate(certificate, public_key, self.client_socket)

        if tmpHash == GatewayPublicKeyHash:

            print_certificate(certificate)

            self.client_socket.send("GATEWAY_KEYS_VERIFIED_BY_CLIENT".encode('utf-8'))

            print("Gatewaykeys verified by Client")
            
            received_aes_data = self.client_socket.recv(2048)

            hashOfEightGateway, session, eightByteGateway = self.set_aes_encryption(received_aes_data)

            if hashOfEightGateway == session: 

                self.AESKey = bytes(eightByteGateway + eightByteGateway[::-1])

                #sends back shared secret if it´s correct
                public_key = RSA.import_key(GatewayPublicKey)
                cipher = PKCS1_OAEP.new(public_key)
                encrypted_data = cipher.encrypt(eightByteGateway)

                self.client_socket.send(encrypted_data)

                gateway_aes_msg = self.client_socket.recv(2048)
                decrypted_aes_data = self.aes_client_decoding(gateway_aes_msg)

                if decrypted_aes_data == b"AES_READY_CLIENT":
                        
                        aes_verified = self.aes_client_encoding(b"AES_VERIFIED_CLIENT")
                        self.client_socket.send(aes_verified)

                        gateway_set_contract = self.client_socket.recv(2048)
                        gateway_set_contract = self.aes_client_decoding(gateway_set_contract)

                        if gateway_set_contract == b"SET_CLIENT_SMART_CONTRAT":

                            ready_flag_smart_contract = self.aes_client_encoding(b"READY_SMART_CONTRACT")
                            self.client_socket.send(ready_flag_smart_contract)

                            smart_contract_data_bytes = self.client_socket.recv(4096)
                            smart_contract_data = self.aes_client_decoding(smart_contract_data_bytes)

                            self.smart_contract_data = pickle.loads(smart_contract_data)

                            print("*************************************************")
                            print("Client Smart Contract: ", self.smart_contract_data)
                            print("*************************************************")

                            received_smart_contract = self.aes_client_encoding(b"RECEIVED_SMART_CONTRACT")
                            self.client_socket.send(received_smart_contract)

                            #getting smart contract from gateway to work
                            enc_serialized_base_smart_contract = self.client_socket.recv(32768)
                            serialized_base_smart_contract = self.aes_client_decoding(enc_serialized_base_smart_contract)
                            gateway_smart_contract_dict = pickle.loads(serialized_base_smart_contract)

                            self.gateway_smart_contract = ClientSmartContract().rebuild_smart_contract(gateway_smart_contract_dict)

                            print("Gateway Smart Contract set up!")

                            self.client_device_key = self.smart_contract_data["AccountId"]
                            self.client_account_address = self.smart_contract_data["AccountAddress"]
            
                            #now client is getting the enc_model and adresses of the servers to control the hash
                            got_smart_contract = self.aes_client_encoding(b"WAIT_FOR_RECON_ID")
                            self.client_socket.send(got_smart_contract)

                            #getting client reconnection id
                            client_reconnection_id = self.client_socket.recv(4096)
                            client_reconnection_id = self.aes_client_decoding(client_reconnection_id)

                            print()
                            print("Client Reconnection ID:", client_reconnection_id.decode("utf-8"))
                            print()

                            self.client_reconnection_id = client_reconnection_id.decode("utf-8")

                            got_reconnection_id = self.aes_client_encoding(b"GOT_RECONNECTION_ID")
                            self.client_socket.send(got_reconnection_id)

                            #client is getting a list of all registered Servers on the BC
                            server_account_addresses = self.client_socket.recv(4096)
                            server_account_addresses = self.aes_client_decoding(server_account_addresses)

                            if server_account_addresses == b"NO_SERVER_AVAILABLE":
                                print("No Server available to connect. Try again later!")
                                self.close_connection()
                                
                            else:

                                try:
                                    server_account_addresses = server_account_addresses.decode("utf-8")
                                    server_account_addresses = json.loads(server_account_addresses)

                                    #checks if server are available

                                except:
                                    print("No Server available to connect!")
                                    self.close_connection()
                               

                                selected_server = self.select_aggregate_server(list(server_account_addresses))
                                selected_server_bytes = str(selected_server).encode("utf-8")
                                selected_server_bytes = self.aes_client_encoding(selected_server_bytes)
                                self.client_socket.send(selected_server_bytes)

                                #smart contract of selected server
                                selected_server_smart_contract = self.client_socket.recv(4096)
                                selected_server_smart_contract = self.aes_client_decoding(selected_server_smart_contract)
                                selected_server_smart_contract = decode_dict(selected_server_smart_contract)

                                print("Selected Server Smart Contract: ", selected_server_smart_contract)

                                #after getting a valid smart contract, the client is connecting with the server
                                if str(selected_server_smart_contract['AccountAddress']) == str(selected_server):

                                    self.selected_server_connection_url = selected_server_smart_contract['ConnectionUrl']
                                    #to check for server if encrypted model was changed
                                    self.enc_model_hash  = selected_server_smart_contract['EncModel']
                                    #to check for server if orginal model was changed
                                    self.model_hash  = selected_server_smart_contract['ModelHash']

                                    #to check for server if client is registered
                                    #self.client_device_key = selected_server_smart_contract['AccountId']

                                    #Client is getting the encrypted model from the Gateway-Server
                                    #is comparing it with the BC and the Hashes
                                    ready_gateway_model = self.aes_client_encoding(b"READY_GATEWAY_MODEL")
                                    self.client_socket.send(ready_gateway_model)

                                    enc_model_gateway = self.client_socket.recv(524288)
                                    enc_model_gateway = self.aes_client_decoding(enc_model_gateway)

                                    enc_global_model = enc_model_gateway.decode("utf-8")

                                    #sent model and received hash are getting compared
                                    verify_end_model_hash = self.hash_model(enc_global_model)

                                    if str(verify_end_model_hash.hexdigest()) == str(self.enc_model_hash):

                                        print("Hash of Enc Models are the same...")

                                        self.enc_global_model = enc_model_gateway

                                        #send that client received model and getting reconnection code
                                        received_gateway_model = self.aes_client_encoding(b"RECEIVED_GATEWAY_MODEL")
                                        self.client_socket.send(received_gateway_model)

                                        client_reconnection_set = self.client_socket.recv(2048)
                                        pickled_client_reconnection_set = self.aes_client_decoding(client_reconnection_set)
                                        self.client_reconnection_set = pickle.loads(pickled_client_reconnection_set)

                                        #connect with server and receiving serverModelEncodeKey
                                        host, port = self.selected_server_connection_url.split(':')

                                        #change GUI while connecting to aggregate server...
                                        self.server_gui()
                                        self.close_connection()
                                        self.build_aggregate_server_connection(host, int(port))
        else:

            print("No Gateway Respond")


    #is selecting a random server address from the list
    def select_aggregate_server(self, server_account_addresses):

        selected_server = random.choice(server_account_addresses)
        return selected_server

    #function to decrypt the ml-model with the servermodeldecodekey
    def decrypt_global_model(self, salt, iv, encryptor_tag, encrypted_data, password):

        password = password.decode()

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(password.encode())

        # Create the cipher
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, encryptor_tag), backend=default_backend())
        decryptor = cipher.decryptor()

        # Decrypt the data
        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

        # Unpad the data
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()

        return data

    
    #hash the model    
    def hash_model(self, global_model):
        
        hashed_global_model = hashlib.sha3_256(str(global_model).encode('utf-8'))
        return hashed_global_model


    #build connection to aggregate server
    def build_aggregate_server_connection(self, host, port):

        self.client_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_server_socket.connect((host, port))

        print(f"Verbindung zum Server {self.host}:{self.port} hergestellt")

        self.client_server_socket.send(b"CLIENT_READY_FOR_RSA")

        server_ready = self.client_server_socket.recv(1024)

        if server_ready == b"SERVER_READY_FOR_RSA":

            self.send_aggregate_server_data()


    #verifying server keys
    def verify_server_keys(self):
        
        serverPH = self.client_server_socket.recv(4096)
        split = serverPH.split(self.delimiter_bytes)

        ServerPublicKey = split[0].decode('utf-8')
        serverPublicKeyHash = split[1].decode('utf-8')

        cleanedServerPublicKey = ServerPublicKey.replace("\r\n", '')
        cleanedServerPublicKeyHash = serverPublicKeyHash.replace("\r\n", '')

        tmpServerPublic_bytes = cleanedServerPublicKey.encode('utf-8')

        tmpHashObject = hashlib.sha3_256(tmpServerPublic_bytes)
        tmpHash = tmpHashObject.hexdigest()

        return tmpHash, cleanedServerPublicKeyHash, ServerPublicKey
    

    def aes_server_decoding(self, data):

        iv = data[:16]
        cipher = Cipher(algorithms.AES(self.AESKeyServer), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_aes_data = decryptor.update(data[16:]) + decryptor.finalize()

        return decrypted_aes_data
    

    def aes_server_encoding(self, data):

        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.AESKeyServer), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(data) + encryptor.finalize()

        return iv + encrypted_data
    

    def send_aggregate_server_data(self):

        #client publickey with its hash gets send
        self.client_server_socket.send(self.public + self.delimiter_bytes + self.client_hash_public.encode('utf-8'))

        tmpHash, ServerPublicKeyHash, ServerPublicKey = self.verify_server_keys()

        cert_path = "./certificates/aggregate_server_cert.pem"
        public_key_path = "./certificates/aggregate_server_public_key.pem"

        certificate = load_certificate(cert_path)
        public_key = load_public_key(public_key_path)

        validate_certificate(certificate, public_key, self.client_socket)

        if tmpHash == ServerPublicKeyHash:

            print_certificate(certificate)

            #is changing the gui before getting the model from the aggergate server
            self.client_server_socket.send(b"SERVER_KEYS_VERIFIED_BY_CLIENT")
            
            print("Serverkeys verified by Client")

            #set up AES with Server
            received_aes_data_server = self.client_server_socket.recv(2048)

            hashOfEightServer, sessionServer, eightByteServer = self.set_aes_encryption(received_aes_data_server)

            if hashOfEightServer == sessionServer: 
                
                self.AESKeyServer = bytes(eightByteServer + eightByteServer[::-1])

                #sends back shared secret if it´s correct
                server_public_key = RSA.import_key(ServerPublicKey)
                cipher_server = PKCS1_OAEP.new(server_public_key)
                encrypted_data = cipher_server.encrypt(eightByteServer)

                self.client_server_socket.send(encrypted_data)

                server_aes_msg = self.client_server_socket.recv(2048)
                decrypted_aes_data_server = self.aes_server_decoding(server_aes_msg)

                #AES Encryption is working
                if decrypted_aes_data_server == b"AES_READY_CLIENT_BY_SERVER":
                    
                    client_aes_ready = self.aes_server_encoding(b"CLIENT_AES_READY")
                    self.client_server_socket.send(client_aes_ready)

                    wait_client_smart_contract = self.client_server_socket.recv(4096)
                    wait_client_smart_contract = self.aes_server_decoding(wait_client_smart_contract)

                    if wait_client_smart_contract == b"WAIT_CLIENT_SMART_CONTRACT":

                        client_contract_data = pickle.dumps(self.smart_contract_data)
                        client_contract_data = self.aes_server_encoding(client_contract_data)
                        self.client_server_socket.send(client_contract_data)

                        wait_enc_model_and_id = self.client_server_socket.recv(1024)
                        wait_enc_model_and_id = self.aes_server_decoding(wait_enc_model_and_id)

                        #sending encrypted model and account ID to server
                        if wait_enc_model_and_id == b"WAIT_ENC_MODEL_AND_ID":

                            enc_model_hash = self.aes_server_encoding(b"CLIENT_WAITING_FOR_MODEL_ENCRYPTION")
                            self.client_server_socket.send(enc_model_hash)

                            encrypted_model_hash_dict_client = self.client_server_socket.recv(524288)
                            encrypted_model_hash_dict_client = self.aes_server_decoding(encrypted_model_hash_dict_client)
                            encrypted_model_hash_dict_client = pickle.loads(encrypted_model_hash_dict_client)
                            
                            enc_model_hash = self.aes_server_encoding(self.enc_model_hash.encode("utf-8"))
                            self.client_server_socket.send(enc_model_hash)

                            #client gets the ServerModelEncodeKey to decrypt finally it´s model
                            server_model_decode_key = self.client_server_socket.recv(1024)
                            server_model_decode_key = self.aes_server_decoding(server_model_decode_key)

                            enc_global_model = self.enc_global_model.decode("utf-8")
                            enc_global_model = enc_global_model[2:-1]
                            enc_global_model = enc_global_model.encode("utf")

                            model = self.decrypt_global_model(encrypted_model_hash_dict_client["salt"],
                                                                           encrypted_model_hash_dict_client["iv"],
                                                                           encrypted_model_hash_dict_client["encryptor_tag"],
                                                                           encrypted_model_hash_dict_client["encrypted_data"],
                                                                           server_model_decode_key)


                            if model:

                                verify_model_hash = self.hash_model(model)

                                #after decrypting the model the hash of the real model gets compared
                                if str(verify_model_hash.hexdigest()) == (self.model_hash):

                                    model_json = pickle.loads(model)
                                    received_server_data = json.loads(model_json)

                                    print("Model is verified! Ready for start training sequence...")

                                    final_model_verification = self.aes_server_encoding(b"RECEIVED_FINAL_MODEL_BY_CLIENT")
                                    self.client_server_socket.send(final_model_verification)

                                    received_model_architecture = received_server_data["model_architecture"]
                                    self.model = model_from_json(received_model_architecture)
                                    self.model.set_weights(decode(received_server_data["model_weights"]))
#
                                    self.model.summary()

                                    waiting_client_data_hash = self.client_server_socket.recv(1024)
                                    waiting_client_data_hash = self.aes_server_decoding(waiting_client_data_hash)

                                    #sending hash of client data...
                                    if waiting_client_data_hash == b"WAITING_FOR_CLIENT_DATA_HASH":

                                        data_concatenate = np.concatenate((self.X_train.reshape(-1), self.X_test.reshape(-1), self.y_train.reshape(-1), self.y_train.reshape(-1)))

                                        hashed_client_data = self.hash_model(data_concatenate)
                                        hashed_client_data_hex = hashed_client_data.hexdigest()
                                        b_hashed_client_data = hashed_client_data_hex.encode("utf-8")

                                        #sending hashed data for server container
                                        client_data_hash = self.aes_server_encoding(b_hashed_client_data)
                                        self.client_server_socket.send(client_data_hash)

                                        enc_client_validation_container = self.client_server_socket.recv(16777216)
                                        pickled_client_validation_container = self.aes_server_decoding(enc_client_validation_container)

                                        client_validation_container = pickle.loads(pickled_client_validation_container)

                                        server_encrypted_msg = client_validation_container.decapsulate_model(received_server_data,
                                                                                                                data_concatenate,
                                                                                                                self.X_train,
                                                                                                                self.y_train,
                                                                                                                self.X_test,
                                                                                                                self.y_test)
                                    

                                        #send to server the result
                                        send_enc_client_result = self.aes_server_encoding(server_encrypted_msg)
                                        self.client_server_socket.send(send_enc_client_result)

                                        client_allowed = self.client_server_socket.recv(4096)
                                        client_allowed = self.aes_server_decoding(client_allowed)

                                        if client_allowed == b"CLIENT_ACCESSED":

                                            self.start_local_training()
                                        
                                        elif client_allowed == b"DETECTED_ANOMALY":

                                            print("Server detected anomaly")
                                            self.close_connection()

                                        else:
                                            print("Client cannot access")
                                            self.close_connection()   
        else:
            print("Serverkeys are not verified")

    #starts the training of the client    
    def start_local_training(self):

        print()
        print("Client starts training...")
        print()

        self.model.compile(optimizer='adam', loss=tf.keras.losses.CategoricalCrossentropy(from_logits=True), metrics=['accuracy'])
        self.model.fit(self.X_train, self.y_train, batch_size=self.batch_size, epochs=self.epochs, validation_data=(self.X_test, self.y_test))

        y_pred_logits = self.model.predict(self.X_test)
        y_pred = np.argmax(y_pred_logits, axis=1)
        y_test_labels = np.argmax(self.y_test, axis=1)

        report = classification_report(y_test_labels, y_pred, target_names=[str(i) for i in range(10)])
        
        print(report)

        self.save_model_weights()


    def save_model_weights(self):   

        model_weights = self.model.get_weights()

        hashed_model_weights = self.hash_model(model_weights)
        hashed_model_weights = hashed_model_weights.hexdigest()

        #check up if DeviceKey makes sense!!!

        model_weights_and_id = {
            "ModelWeights": model_weights,
            "DeviceKey": f"{self.client_account_address}"
        }

        final_model_weights = pickle.dumps(model_weights_and_id)

        #set up model weights into the BC
        self.smart_contract_data  = ClientSmartContract().set_client_model_weights(
                                                                                 hashed_model_weights,
                                                                                 self.client_account_address,
                                                                                 self.gateway_smart_contract)

        print("***********************************************************")
        print("")
        print("Updated Client Smart Contract: ", self.smart_contract_data )
        print("")
        print("***********************************************************")

        print("Client Model Weights saved and tries to reconnect to gateway...")

        if self.last_training_round is False:

            #reconnect with gateway server to send model weights
            self.test_connect(final_model_weights)

        else:
            print()
            print("Last Training Round, client stopped training...")
            print()


    def gateway_reconnection(self, final_model_weights):

        self.client_socket.send(self.client_reconnection_id.encode("utf-8"))

        gateway_aes_ready = self.client_socket.recv(4096)
        
        if gateway_aes_ready == b"CLIENT_WAIT":

            print()
            print("Client has to wait until aggregate server has finished")
            print()

            self.test_connect(final_model_weights)

        elif gateway_aes_ready == b"GATEWAY_READY_FOR_RSA":

            print()
            print("Client Reconnection ID", self.client_reconnection_id)
            print()

            #send client public key for aes reconnection
            client_public_key_message = self.public + self.delimiter_bytes + self.client_hash_public.encode('utf-8')
            self.client_socket.send(client_public_key_message)   

            tmpHash, GatewayPublicKeyHash, GatewayPublicKey = self.verify_gateway_keys()

            if tmpHash == GatewayPublicKeyHash:

                print("Gateway keys verified")

                self.client_socket.send(b"GATEWAY_KEYS_VERIFIED_BY_CLIENT")

                received_aes_data = self.client_socket.recv(2048)

                hashOfEightGateway, session, eightByteGateway = self.set_aes_encryption(received_aes_data)

                if hashOfEightGateway == session: 

                    print("Received aes set up")

                    self.AESKey = bytes(eightByteGateway + eightByteGateway[::-1])

                    #sends back shared secret if it´s correct
                    public_key = RSA.import_key(GatewayPublicKey)
                    cipher = PKCS1_OAEP.new(public_key)
                    encrypted_data = cipher.encrypt(eightByteGateway)

                    self.client_socket.send(encrypted_data)

                    gateway_aes_msg = self.client_socket.recv(2048)
                    decrypted_aes_data = self.aes_client_decoding(gateway_aes_msg)

                    if decrypted_aes_data == b"AES_READY_CLIENT":

                        aes_verified = self.aes_client_encoding(b"AES_VERIFIED_CLIENT")
                        self.client_socket.send(aes_verified)

                        server_wait_reconnection_code = self.client_socket.recv(1024)
                        server_wait_reconnection_code = self.aes_client_decoding(server_wait_reconnection_code)

                        if server_wait_reconnection_code == b"SERVER_WAIT_RECONNECTION_CODE":

                            send_reconnection_set = self.aes_client_encoding(pickle.dumps(self.client_reconnection_set))
                            self.client_socket.send(send_reconnection_set)

                            print("Client sending reconnection set")

                            #get response from gateway with new reconnection id
                            new_reconnection_id = self.client_socket.recv(1024)
                            new_reconnection_id  = self.aes_client_decoding(new_reconnection_id)
                            self.client_reconnection_id = new_reconnection_id.decode("utf-8") 

                            print()
                            print("New Client Reconnection ID", self.client_reconnection_id)
                            print()

                            client_host_port_dict = {
                                "host": self.client_host,
                                "port": self.client_port
                            }

                            client_host_port_dict = pickle.dumps(client_host_port_dict)

                            enc_client_host_port_dict = self.aes_client_encoding(client_host_port_dict)
                            self.client_socket.send(enc_client_host_port_dict)

                            received_client_host_port = self.client_socket.recv(1024)
                            received_client_host_port = self.aes_client_decoding(received_client_host_port)

                            if received_client_host_port == b"GATEWAY_RECEIVED_CLIENT_HOST_PORT":
                        
                                if self.has_send_model_weights == False:
                            
                                    print()
                                    print("Sending client model weights")
                                    print()

                                    self.send_model_weights(final_model_weights)

            else:
                print("Gateway keys are wrong")


    def test_connect(self, final_model_weights):

        while True:

            try:

                self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                gateway_address = (self.gateway_host, self.gateway_port)
                self.client_socket.connect(gateway_address)

                print()
                print(f"Reconnection to Gateway-Server {self.gateway_host}:{self.gateway_port}")
                print()
            
                gateway_open_thread = self.client_socket.recv(1024)

                if gateway_open_thread == b"OPEN_THREAD":

                    print("Thread is open")

                    print(self.client_socket)
                    self.gateway_reconnection(final_model_weights)
                    break

                elif gateway_open_thread == b"SERVER_BUSY":
                    print("Server is busy, retrying...")
                    self.close_connection()
                    time.sleep(5)
            
            except ConnectionRefusedError:
                print("Connection refused, retrying...")
                time.sleep(5)
                
            except Exception as e:
                print(f"An error occurred: {e}")
                self.close_connection()
                time.sleep(5)


    #sending model weights to gateway
    def send_model_weights(self, final_model_weights):

        ready_send_model_weights = self.aes_client_encoding(b"CLIENT_WILL_SEND_MODEL_WEIGHTS")
        self.client_socket.send(ready_send_model_weights)

        gateway_ready_model_weights = self.client_socket.recv(1024)
        gateway_ready_model_weights  = self.aes_client_decoding(gateway_ready_model_weights)

        if gateway_ready_model_weights == b"GATEWAY_READY_FOR_MODEL_WEIGHTS":

            print("Gateway is waiting for Model Weights")

            final_model_weights = self.aes_client_encoding(final_model_weights)
            self.client_socket.send(final_model_weights)

            gateway_model_weights_received = self.client_socket.recv(1024)
            gateway_model_weights_received  = self.aes_client_decoding(gateway_model_weights_received)

            if gateway_model_weights_received == b"CLIENT_MODEL_WEIGHTS_RECEIVED":

                print()
                print("Gateway received Model Weights")
                print()

                self.has_send_model_weights = True

                #reconnect with gateway server to send model weights
                #gateway should reconnect with client!
                self.client_socket.close()

                #start client server waiting for gateway server
                self.server_socket_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.server_socket_client.bind((self.client_host, self.client_port))
                self.server_socket_client.listen(1)

                print()
                print("Client in server position is waiting for client model weights from server")
                print()

                gateway_socket, gateway_address = self.server_socket_client.accept()
                
                if self.has_send_model_weights:

                    gateway_ready = gateway_socket.recv(1024)

                    if gateway_ready == b"GATEWAY_SEND_UPDATED_MODEL_WEIGHTS":

                        gateway_socket.send(b"CLIENT_WAITING_FOR_MODEL_WEIGHTS_UPDATE")
            
                        print()
                        print("Receiving Model weights update from gateway")
                        print()

                        self.get_updated_model_weights(gateway_socket)

                    elif gateway_ready == b"GATEWAY_SEND_UPDATED_MODEL_WEIGHTS_FINAL":

                        #set last round to stop training afterwards
                        self.last_training_round = True

                        gateway_socket.send(b"CLIENT_WAITING_FOR_MODEL_WEIGHTS_UPDATE")
            
                        print()
                        print("Receiving Model weights update from gateway")
                        print()

                        self.get_updated_model_weights(gateway_socket)
                

    #waiting for feedback of gateway if closing or start training again...
    def get_updated_model_weights(self, gateway_socket):

        updated_server_model_weights = gateway_socket.recv(262144)
        gateway_socket.close()
        self.server_socket_client.close()
        
        self.set_updated_model_weights(updated_server_model_weights)


    def set_updated_model_weights(self, updated_server_model_weights_pickled):

        updated_server_model_weights_dict = pickle.loads(updated_server_model_weights_pickled)

        server_account_address = updated_server_model_weights_dict["ServerAccountAddress"]
        server_updated_model_weights = updated_server_model_weights_dict["ServerModelWeights"]

        #if model weigths sent from gateway are correct than new model weights get set and the training starts again
        if self.verify_server_model_weights(server_account_address, server_updated_model_weights):
                
                self.has_send_model_weights = False

                if self.model is not None:

                    self.model.set_weights(server_updated_model_weights)

                    self.model.summary()
                    self.start_local_training()


    #checks if client really exists in BC and if model weights has changed
    def verify_server_model_weights(self, server_account_address, server_updated_model_weights):

        server_updated_model_weights_hash = self.hash_model(server_updated_model_weights)
        
        server_smart_contract_model_weights = ClientSmartContract().get_server_model_weights_hash_client(server_account_address,
                                                                                        self.client_account_address,
                                                                                        self.gateway_smart_contract)
        print()
        print("Server Smart Contract", server_smart_contract_model_weights)
        print()

        if str(server_smart_contract_model_weights["ServerModelWeightsHash"]) == str(server_updated_model_weights_hash.hexdigest()):

            print()
            print("Client verified. Global Model Weights from Server were not changed")
            print()
            return True


    def close_connection(self):
        self.client_socket.close()
        print("Client Connection closed")



if __name__ == "__main__":

    root = customtkinter.CTk()
    root.config(bg="black")
    root.title("SICKFL")
    root.config(height=800, width=1200)
    server = Client(root)
    root.mainloop()


"""
def create_client_instance():

    root = customtkinter.CTk()
    root.config(bg="black")
    root.title("SICKFL")
    root.config(height=800, width=1200)
    server = Client(root)
    root.mainloop()


if __name__ == "__main__":

    num_times = 2  

    processes = []
    
    for _ in range(num_times):
        p = Process(target=create_client_instance)
        p.start()
        processes.append(p)

    for p in processes:
        p.join()
"""