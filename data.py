
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import codecs
import pickle
import numpy as np
import tensorflow as tf
from sklearn.model_selection import train_test_split


#TEST MODEL DATA

def get_data():

    #calls data from folder
    data_path='./data/synthetic_network_traffic_short.csv'

    data = pd.read_csv(data_path)

    X, y = prepare_data(data)

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)
    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test = scaler.transform(X_test)

    return X_train, y_train, X_test, y_test


def prepare_data(data):

    #prepares the data for the model

    data['TotalBytes'] = data['BytesSent'] + data['BytesReceived']
    data['TotalPackets'] = data['PacketsSent'] + data['PacketsReceived']

    anomaly_data = data[data['IsAnomaly'] == 1]
    oversampled_data = pd.concat([data, anomaly_data], axis=0)

    X = oversampled_data.drop(columns=['IsAnomaly'])
    y = oversampled_data['IsAnomaly']  

    return X, y


#MNIST MODEL

def get_second_data():

    def create_non_iid_data(x, y):

        #number of groups in the dataset, can be variable between 1 and 10
        num_partitions=3

        partitions = [[] for _ in range(num_partitions)]
        labels = [[] for _ in range(num_partitions)]
        
        #classes of mnist from 0 to 9
        class_distribution = [
            [0, 1, 2, 3],  
            [4, 5, 6],     
            [7, 8, 9]      
        ]
        
        for i in range(num_partitions):
            
            indices = np.where(np.isin(y, class_distribution[i]))[0]
            x_partition, _, y_partition, _ = train_test_split(x[indices], y[indices], test_size=0.5, random_state=42)
            partitions[i] = x_partition
            labels[i] = y_partition
        
        return partitions, labels


    (x_train, y_train), (x_test, y_test) = tf.keras.datasets.mnist.load_data()

    partitions, labels = create_non_iid_data(x_train, y_train)
    
    x_train_non_iid = np.concatenate(partitions)
    y_train_non_iid = np.concatenate(labels)

    X_train = x_train_non_iid.reshape(-1, 28, 28, 1).astype('float32') / 255.0
    X_test = x_test.reshape(-1, 28, 28, 1).astype('float32') / 255.0

    y_train = tf.keras.utils.to_categorical(y_train_non_iid, 10)
    y_test = tf.keras.utils.to_categorical(y_test, 10)


    return X_train, y_train, X_test, y_test


#poisons the data by flipping class 1 with 9
def data_poisoning():
    
    def create_non_iid_partitions(x, y, num_partitions=3):
        partitions = [[] for _ in range(num_partitions)]
        labels = [[] for _ in range(num_partitions)]
        
        class_distribution = [
            [0, 1, 2, 3],  
            [4, 5, 6],     
            [7, 8, 9]      
        ]
        
        for i in range(num_partitions):
            indices = np.where(np.isin(y, class_distribution[i]))[0]
            x_partition, _, y_partition, _ = train_test_split(x[indices], y[indices], test_size=0.5, random_state=42)
            partitions[i] = x_partition
            labels[i] = y_partition
        
        return partitions, labels

    (x_train, y_train), (x_test, y_test) = tf.keras.datasets.mnist.load_data()


    def flip_labels(y_train, label1, label2):
        flipped_y_train = np.copy(y_train)
        flipped_y_train[y_train == label1] = label2
        flipped_y_train[y_train == label2] = label1
        return flipped_y_train

    flipped_y_train = flip_labels(y_train, 1, 9)

    partitions, labels = create_non_iid_partitions(x_train, flipped_y_train)
    
    x_train_non_iid = np.concatenate(partitions)
    y_train_non_iid = np.concatenate(labels)

    x_train_non_iid = x_train_non_iid.reshape(-1, 28, 28, 1).astype('float32') / 255.0
    x_test = x_test.reshape(-1, 28, 28, 1).astype('float32') / 255.0

    flipped_y_train_cat = tf.keras.utils.to_categorical(y_train_non_iid, 10)
    y_test_cat = tf.keras.utils.to_categorical(y_test, 10)

    return x_train_non_iid, flipped_y_train_cat, x_test, y_test_cat


def data_poisoning_extrem():
    
    def flip_labels(y_train, label1, label2):
        flipped_y_train = np.copy(y_train)
        flipped_y_train[y_train == label1] = label2
        flipped_y_train[y_train == label2] = label1
        return flipped_y_train

    def create_non_iid_partitions(x, y, num_partitions=3):
        partitions = [[] for _ in range(num_partitions)]
        labels = [[] for _ in range(num_partitions)]
        
        class_distribution = [
            [0, 1, 2, 3],  
            [4, 5, 6],     
            [7, 8, 9]      
        ]
        
        for i in range(num_partitions):
            indices = np.where(np.isin(y, class_distribution[i]))[0]
            x_partition, _, y_partition, _ = train_test_split(x[indices], y[indices], test_size=0.5, random_state=42)
            partitions[i] = x_partition
            labels[i] = y_partition
        
        return partitions, labels

    (x_train, y_train), (x_test, y_test) = tf.keras.datasets.mnist.load_data()

    # Flip labels for 1 with 9, 2 with 7, and 3 with 8
    flipped_y_train = flip_labels(y_train, 1, 9)
    flipped_y_train = flip_labels(flipped_y_train, 2, 7)
    flipped_y_train = flip_labels(flipped_y_train, 3, 8)

    partitions, labels = create_non_iid_partitions(x_train, flipped_y_train)
    
    x_train_non_iid = np.concatenate(partitions)
    y_train_non_iid = np.concatenate(labels)

    x_train_non_iid = x_train_non_iid.reshape(-1, 28, 28, 1).astype('float32') / 255.0
    x_test = x_test.reshape(-1, 28, 28, 1).astype('float32') / 255.0

    flipped_y_train_cat = tf.keras.utils.to_categorical(y_train_non_iid, 10)
    y_test_cat = tf.keras.utils.to_categorical(y_test, 10)

    return x_train_non_iid, flipped_y_train_cat, x_test, y_test_cat


def decode(b64_str):
    return pickle.loads(codecs.decode(b64_str.encode(), "base64"))

def encode_layer(layer):
    return codecs.encode(pickle.dumps(layer), "base64").decode()