import math
import numpy as np
from keras.utils import plot_model
from keras.layers import Embedding, Conv1D, MaxPooling1D, Dense, Activation, Flatten, Input, Multiply, Dropout
from keras import Model
from keras.models import model_from_json
from sklearn.model_selection import KFold
from keras import optimizers
from sklearn.metrics import confusion_matrix
from keras.callbacks import LearningRateScheduler
import exp_util

import sys
sys.path.append('../')
import util

import os
os.environ["CUDA_DEVICE_ORDER"] = "PCI_BUS_ID"   # see issue #152
os.environ["CUDA_VISIBLE_DEVICES"] = "2"

#MAX_LENGTH = 2188056
MAX_LENGTH = exp_util.MAX_LENGTH
INITIAL_LEARNING_RATE = 0.001

def read_content(df):
    byte_array = bytearray(util.read_sample(src=df['source'], packer_name=df['packer_name'], sample_sha1=df['sample_sha1'],
        unpacked_sample_sha1=df['unpacked_sample_sha1']))[:MAX_LENGTH]
    byte_array = byte_array + bytearray([0] * (MAX_LENGTH - len(byte_array)))
    
    return np.asarray(byte_array)

def exp_decay(epoch, lrate):
    # lrate = INITIAL_LEARNING_RATE
    # k = 0.025
    # lrate = initial_lrate * math.exp(-k * epoch)
    if epoch == 5:
        lrate = lrate / 2
        print("learning_rate: {}".format(lrate))
    return lrate

class NeuralNet:

    def plot(self, filename='model.png'):
        self.model.summary()
        plot_model(self.model, to_file=filename, show_shapes=True)

    def _new_model(self):
        input = Input(shape=(MAX_LENGTH, ))
        a = Embedding(256, 8, name='Embedding')(input)
        b = Conv1D(128, 500, strides=500, name='Conv1D')(a)
        bb = Activation('sigmoid', name='Sigmoid')(Conv1D(128, 500, strides=500)(a))
        gate = Multiply()([b, bb])
        c = MaxPooling1D(name='MaxPooling')(gate)
        d = Flatten()(c)
        e = Dense(128, activation="relu", name='Dense')(d)
        ee = Dropout(0.35)(e)
        f = Dense(2, activation='softmax', name='Softmax')(ee)
        model = Model(inputs=input, outputs=f)
        # opt = optimizers.RMSprop(lr=0.001, rho=0.9, epsilon=None, decay=1e-6)
        # opt = optimizers.SGD(lr=INITIAL_LEARNING_RATE, decay=1e-6, momentum=0.9, nesterov=True)
        opt = optimizers.Adam()
        model.compile(optimizer=opt, loss='categorical_crossentropy', metrics=['accuracy'])
        return model


    def _load_model(self, filename):
        json_file = open(filename + '.json', 'r')
        loaded_model_json = json_file.read()
        json_file.close()
        loaded_model = model_from_json(loaded_model_json)
        # load weights into new model
        loaded_model.load_weights(filename + ".h5")
        return loaded_model

    def fit(self, x, y, epochs, batch_size):
        self.model.fit(x, y, epochs=epochs, batch_size=batch_size, verbose=2)
        #self.model.fit(x, y, epochs=epochs, callbacks=[lrate], batch_size=batch_size)

    def fit_generator(self, generator, validation_generator, epochs):
        lrate = LearningRateScheduler(exp_decay)
        self.model.fit_generator(generator=generator, validation_data=validation_generator, epochs=epochs, callbacks=[lrate])

    def save_model(self, filename):
        model_json = self.model.to_json()
        with open(filename + '.json', "w") as jf:
            jf.write(model_json)
        self.model.save_weights(filename + '.h5')

    def model_score(self, x):
        if len(x) == 0:
            return 0, 0, 0, 0, []
        y_true = [int(l) for l in list(x['malicious'])]
        probabilities = self.model.predict_generator(
            generator=DataGenerator(df=x, to_fit=False,
                                    batch_size=32, dim=exp_util.MAX_LENGTH, n_classes=2, shuffle=False))
        conf_dist = [[float(p[0]), float(p[1])] for p in probabilities]
        
        y_pred = probabilities > 0.5
        y_pred = [int(y[1]) for y in y_pred]
        
        # just adding each possible state, to avoid stupid confusion_matrix
        y_true.extend([0, 0, 1, 1])
        y_pred.extend([1, 0, 1, 0])
        l = list(confusion_matrix(y_true, y_pred).ravel())  # (tn, fp, fn, tp)
        l = [x-1 for x in l]
        
        print("Confusion Matrix: {}".format(l))
        l.append(conf_dist)
        return l

    def __init__(self, filename=None):
        if filename:
            self.model = self._load_model(filename)
        else:
            self.model = self._new_model()


from tensorflow.keras.utils import Sequence


class DataGenerator(Sequence):
    """Generates data for Keras
    Sequence based data generator. Suitable for building data generator for training and prediction.
    """
    def __init__(self, df, to_fit, batch_size, dim, n_classes, shuffle=True):
        """Initialization
        :param to_fit: True to return X and y, False to return X only
        :param batch_size: batch size at each iteration
        :param dim: tuple indicating image dimension
        :param n_classes: number of output masks
        :param shuffle: True to shuffle label indexes after every epoch
        """
        self.df = df
        self.to_fit = to_fit
        self.batch_size = batch_size
        self.dim = dim
        self.n_classes = n_classes
        self.shuffle = shuffle
        self.on_epoch_end()

    def __len__(self):
        """Denotes the number of batches per epoch
        :return: number of batches per epoch
        """
        return int(np.floor(len(self.df) / self.batch_size))

    def __getitem__(self, index):
        """Generate one batch of data
        :param index: index of the batch
        :return: X and y when fitting. X only when predicting
        """
        # Generate indexes of the batch
        data = self.df[index * self.batch_size:(index + 1) * self.batch_size]
        X = np.empty((self.batch_size, self.dim))

        for index, (_, row) in enumerate(data.iterrows()):
            content = read_content(row.to_dict())
            X[index,] = content

        if self.to_fit:
            y = np.asarray(data[['benign', 'malicious']].values)
            return X, y
        else:
            return X

    def on_epoch_end(self):
        """Updates indexes after each epoch
        """
        if self.shuffle is True:
            self.df = self.df.sample(frac=1)
