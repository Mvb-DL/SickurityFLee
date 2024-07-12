#utils function for all
import json, pickle
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import tensorflow as tf
import numpy as np
from keras.models import model_from_json
from commands.server_commands import commands
from sklearn.metrics import classification_report
import pandas as pd
from sklearn.decomposition import PCA
from sklearn.model_selection import train_test_split


def get_command_value(command_key):
    return commands.get(command_key)


#hash the model
def hash_model(global_model):
        
    hashed_global_model = hashlib.sha3_256(str(global_model).encode('utf-8'))
    return hashed_global_model
    

def encode_dict(_dict):

    dict_json = json.dumps(_dict, ensure_ascii=False)
    dict_json_bytes = dict_json.encode("utf-8")

    return dict_json_bytes


def decode_dict(_dict_json_bytes):

    _dict_json = _dict_json_bytes.decode("utf-8")
    _dict = json.loads(_dict_json)

    return _dict


#gets modelhash and data hash from client before sending 
class ClientValidationContainer:

    def __init__(self, model_hash, client_data_hash, server_model_data, server_public_key):

        self.__model_hash = model_hash
        self.__client_data_hash = client_data_hash
        self.__server_model_data = server_model_data
        self.__server_public_key = server_public_key

    @property
    def model_hash(self):
        return self.__model_hash
    
    @property
    def client_data_hash(self):
        return self.__client_data_hash
    
    @property
    def server_model_data(self):
        return self.__server_model_data
    
    @property
    def server_public_key(self):
        return self.__server_public_key


    def verify_data(self, client_data_hash_by_client):

        if self.__client_data_hash == client_data_hash_by_client.encode("utf-8"):
            
            print("Datahash by Client and server are both same")
            return True
    
    def verify_model(self, client_model_hash_by_client):

        if str(self.__model_hash) == str(client_model_hash_by_client):

            print("Modelhash by Client and server are both same")
            return True
        

    def validate_client_data(self, server_model_data, client_overwritten_X_train, client_overwritten_y_train):

        def set_pca(server_X_train_flat, client_X_train_flat):

            pca = PCA(n_components=2)
            pca.fit(server_X_train_flat)
            pca_server = pca.transform(server_X_train_flat)
            pca_client = pca.transform(client_X_train_flat)

            return pca_server, pca_client
        
        # Class averages based on the PCA-transformed data
        def calculate_class_means(pca_data, y_data):

            class_means = {}
            num_classes = y_data.shape[1]

            for i in range(num_classes):

                class_indices = np.where(np.argmax(y_data, axis=1) == i)[0]

                if class_indices.size > 0:  
                    class_means[i] = np.mean(pca_data[class_indices], axis=0)
                else:
                    class_means[i] = np.nan * np.ones(pca_data.shape[1])  

            return class_means


        def display_diff(means_server, means_client):

            mean_differences = {i: np.nan if np.isnan(means_server[i]).any() or np.isnan(means_client[i]).any() else np.linalg.norm(means_server[i] - means_client[i]) for i in means_server}

            all_data = pd.DataFrame(list(mean_differences.items()), columns=['class', 'difference'])

            sorted_differences = sorted([(class_id, diff) for class_id, diff in mean_differences.items() if not np.isnan(diff)], key=lambda x: x[1], reverse=True)
            top_outliers = sorted_differences[:2]

            top_class_outliers = pd.DataFrame(top_outliers, columns=['class', 'difference'])

            return all_data, top_class_outliers
        

        #data of the server
        server_X_train = server_model_data["X_train"]
        server_y_train = server_model_data["y_train"]

        #data of the client to compare
        client_X_train = client_overwritten_X_train
        client_y_train = client_overwritten_y_train

        #prepare the data of server and client to reduce the dimensonality
        server_X_train_flat = server_X_train.reshape(server_X_train.shape[0], -1)
        client_X_train_flat = client_X_train.reshape(client_X_train.shape[0], -1)

        #set the pca following sklearn-framework
        pca_server, pca_client = set_pca(server_X_train_flat, client_X_train_flat)

        means_server = calculate_class_means(pca_server, server_y_train)
        means_client = calculate_class_means(pca_client, client_y_train)

        #using pandas to find the differences and the two classes which have the biggest difference
        all_data, top_class_outliers = display_diff(means_server, means_client)
        
        #at the end it shows the difference between the data of the server and client and the two classes which have the biggest difference (maybe cause of label flipping)
        return all_data, top_class_outliers
       

    def validate_client_model_performance(self, client_model_by_client, overwritten_X_train, overwritten_y_train, overwritten_X_test, overwritten_y_test):

        model_architecture = model_from_json(client_model_by_client["model_architecture"])

        model_architecture.compile(optimizer='adam', loss=tf.keras.losses.CategoricalCrossentropy(from_logits=True), metrics=['accuracy'])
        model_architecture.fit(overwritten_X_train, overwritten_y_train, batch_size=16, epochs=1, validation_data=(overwritten_X_test, overwritten_y_test))

        y_pred_logits = model_architecture.predict(overwritten_X_test)
        y_pred = np.argmax(y_pred_logits, axis=1)
        y_test_labels = np.argmax(overwritten_y_test, axis=1)

        class_report = classification_report(y_test_labels, y_pred, target_names=[str(i) for i in range(10)], output_dict=True, zero_division=0)
        class_report = pd.DataFrame(class_report).transpose()

        client_test_loss, client_test_accuracy = model_architecture.evaluate(overwritten_X_test, overwritten_y_test)
      
        client_model_test_validation = {
                                        "ClassReport": class_report,
                                        "ClientTestLoss": float(client_test_loss),
                                        "ClientTestAccuracy": float(client_test_accuracy)
                                        }

        return client_model_test_validation

        

    #client gets the model from server and the datasize of the training data for the model
    def decapsulate_model(self, client_model_by_client, client_data_by_client, X_train, y_train, X_test, y_test):

        #hashes the model from client
        client_model_hash_by_client = hashlib.sha3_256(str(client_model_by_client).encode('utf-8')).hexdigest()

        #hash the data from client
        client_data_hash_by_client = hashlib.sha3_256(str(client_data_by_client).encode('utf-8')).hexdigest()

        if self.verify_data(client_data_hash_by_client):

            if self.verify_model(client_model_hash_by_client):

                    b_server_model_data = self.__server_model_data
                    server_model_data = pickle.loads(b_server_model_data)

                    overwritten_X_train, _, overwritten_y_train, _ = train_test_split(X_train, y_train, test_size=0.9, random_state=20)
                    overwritten_X_test, _, overwritten_y_test, _ = train_test_split(X_test, y_test, test_size=0.9, random_state=20) 

                    print()
                    print("Overwritten Model Inputs: ", len(overwritten_X_train),
                                                        len(overwritten_y_train),
                                                        len(overwritten_X_test),
                                                        len(overwritten_y_test))
                    print()

                    #verify client data on anomalies
                    all_class_data, class_outliers = self.validate_client_data(server_model_data, overwritten_X_train, overwritten_y_train)

                    client_model_test_validation = self.validate_client_model_performance(client_model_by_client, overwritten_X_train, overwritten_y_train, overwritten_X_test, overwritten_y_test)

                    client_model_test_data = {
                        "AllClassData": all_class_data,
                        "ClassOutliers": class_outliers,
                        "ClassReport": client_model_test_validation["ClassReport"],
                        "ClientTestLoss": client_model_test_validation["ClientTestLoss"],
                        "ClientTestAccuracy": client_model_test_validation["ClientTestAccuracy"],
                    }

                    pickled_client_model_test_data = pickle.dumps(client_model_test_data)

                    rsa_key = RSA.import_key(self.__server_public_key)
                    cipher_rsa = PKCS1_OAEP.new(rsa_key)

                    #too long for rsa
                    #result get´s encrypted automatically and just server can decrypt it!
                    chunk_size = rsa_key.size_in_bytes() - 2 * cipher_rsa._hashObj.digest_size - 2
                    chunks = [pickled_client_model_test_data [i:i + chunk_size] for i in range(0, len(pickled_client_model_test_data), chunk_size)]

                    encrypted_chunks = [cipher_rsa.encrypt(chunk) for chunk in chunks]
    
                    encrypted_message = b''.join(encrypted_chunks)

                    return encrypted_message