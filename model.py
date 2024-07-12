from tensorflow.keras import layers
from tensorflow import keras


def get_model():

    X_train_shape = 12

    model = keras.Sequential([
        layers.Input(shape=(X_train_shape,)),
        layers.Dense(64, activation='relu'),
        layers.Dense(32, activation='relu'),
        layers.Dense(1, activation='sigmoid')  
    ])


    return model


def get_second_model():

    model = keras.Sequential([
        layers.Conv2D(16, kernel_size=(5, 5), padding='same', input_shape=(28, 28, 1)),
        layers.BatchNormalization(),
        layers.ReLU(),
        layers.MaxPooling2D(pool_size=(2, 2)),

        layers.Conv2D(32, kernel_size=(5, 5), padding='same'),
        layers.BatchNormalization(),
        layers.ReLU(),
        layers.MaxPooling2D(pool_size=(2, 2)),

        layers.Flatten(),
        layers.Dense(10)
    ])

    return model

