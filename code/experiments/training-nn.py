import pandas as pd
import numpy as np
import datetime
from time import sleep
import os
import sys
from copy import copy
import pathlib
import sqlite3
import random
import importlib
import ujson as json

sys.path.append('../')
import util
import exp_util

from neuralnet import NeuralNet, DataGenerator
'''
Main module that contains functions to run an experiment of the paper.

Usage:
    python3 training.py config_exp0

Dependencies:
    * config_exp0.py: a python file that contains settings for the experiment
    * actor.py: threading module for running experiment concurrently

Notes:
    * if config.n_workers is set to 1 the experiments are runned in the main thread sequentially
    * debug is a global used to print additional informations
    * the seed is fixed and every thread uses it (summed with #round) for reproducibility
'''


NUMPY_SEED = 17
EPOCHS = 5
BATCH_SIZE = 64
debug = True

def dprint(*obj):
    '''
    helper function
    :param obj: string or iterable to print if debug is set
    '''
    global debug
    if debug:
        print('-- DEBUG:', *obj)

def get_model():
    '''
    :param model_name: The name of the classifier
    '''
    return NeuralNet()

def main(conf_file=''):
    '''
    This function iterates between different ratio of malicious / benign, packed/unpacked
    It evaluates an sklearn model for the given model_name against the dataset
    :param conf_file: Location of the configuration file
    :rtype None
    '''
    global debug
    assert conf_file != ''
    if conf_file[-3:] == '.py':
        conf_file = conf_file[:-3]
    print('Using as configuration file:', conf_file)
    conf = importlib.import_module(conf_file)
    model_name = conf.model_name
    assert model_name == 'nn'
    df = conf.dataframe
    database_location = conf.database
    combs = conf.iterations
    global MAX_LENGTH, RES_DIR
    MAX_LENGTH = exp_util.MAX_LENGTH
    RES_DIR = conf.res_dir
    print("Using", model_name, "as classifier")
    df = conf.process_dataset(df, NUMPY_SEED)

    packed_benign       = df[(df.benign == 1) & (df.packed == 1)].index.to_frame()
    unpacked_benign     = df[(df.benign == 1) & (df.packed == 0)].index.to_frame()
    packed_malicious    = df[(df.benign == 0) & (df.packed == 1)].index.to_frame()
    unpacked_malicious  = df[(df.benign == 0) & (df.packed == 0)].index.to_frame()


    indices = (packed_benign, unpacked_benign, packed_malicious, unpacked_malicious)

    dprint("four sets indices are ready now!")

    # Create table
    conn = sqlite3.connect(database_location)
    cur = conn.cursor()
    try:
        cur.execute('''CREATE TABLE results
                  (ratio_mal real, ratio_ben real, round integer, features text, weights text, results text, confidence text)''')
        conn.commit()
    except:
        pass

    done = list(cur.execute('select ratio_ben, ratio_mal, round from results'))
    if done:
        print('Total iterations is:', len(combs))
        combs = list(set(combs) - set(done))
    print('Number of iterations remaining:', len(combs))

    for query in run_mono(df, indices, combs, conf.divide_dataset):
        cur.execute(*query)
        conn.commit()

def run_mono(df, indices, combs, divide_fun):
    '''
    Run the experiments in a linear fashion. No concurrency, useful for debugging.
    :param df: tuple of (packed ben, unpacked ben, packed mal, unpacked mal)
    :param indices: store indices for four sets of packed_benign, unpacked_benign, packed_malicious, unpacked_malicious
    :param combs: the combinations of (ratio_ben, ratio_mal, round) as defined by config file
    :rtype: yield string (sql query to be executed)
    '''
    cnt = len(combs)
    for c in combs:
        ratio_ben, ratio_mal, round = c
        dprint('starting experiment')
        res = experiment(df, indices, (ratio_ben, ratio_mal), round, divide_fun)
        dprint('dumping res["results"]')
        results = json.dumps(res['results'])
        features = json.dumps({})
        weights = json.dumps({})
        conf = json.dumps(res['confidence'])
        dprint('dumping res["confidence"]')
        query = ('''INSERT INTO results VALUES (?, ?, ?, ?, ?, ?, ?)''',
                (ratio_mal, ratio_ben, round, features, weights, results, conf))
        dprint('yielding query of size:', len(query))
        cnt -= 1
        dprint('{} remaining'.format(cnt))
        yield query


def read_content(df):
    return util.read_sample(src=df['source'], packer_name=df['packer_name'], sample_sha1=df['sample_sha1'],
                            unpacked_sample_sha1=df['unpacked_sample_sha1'])


def experiment(df, indices, ratio, round, divide_fun):
    '''
    Single round of the experiment for a determined ratio.
    The model is instantied, trained, tested against a dataset
    and results are stored
    :param df: pandas dataframe containing the feature vector for all the samples
    :param indices: store indices for four sets of packed_benign, unpacked_benign, packed_malicious, unpacked_malicious
    :param ratio: Tuples of ratio of benign / malicious packed
    :param round: counter of rounds
    :param divide_fun: function to divide the dataset, defined in config
    :rtype Dictionary
    '''
    id = '{}-{}-{}'.format(ratio[0], ratio[1], round)
    dprint('Entered experiment:', id)
    ratio_ben, ratio_mal = ratio

    # split between test, train
    training_packed_benign, testing_packed_benign, training_unpacked_benign, testing_unpacked_benign, training_packed_malicious, testing_packed_malicious, training_unpacked_malicious, testing_unpacked_malicious = divide_fun(indices, ratio_ben, ratio_mal, NUMPY_SEED+round)
    # training_packed_benign, testing_packed_benign, training_unpacked_benign, testing_unpacked_benign, training_packed_malicious, testing_packed_malicious, training_unpacked_malicious, testing_unpacked_malicious = divide_fun(df, ratio_ben, ratio_mal, NUMPY_SEED+round)

    # dprint('dividing dataset')
    train_indices = training_packed_malicious + training_packed_benign + training_unpacked_malicious + training_unpacked_benign
    x_train = df[df.index.isin(train_indices)]
    x_train = x_train.sample(frac=1, random_state=NUMPY_SEED + round)
    dprint('done with dividing')

    # train model on training set
    model = get_model()
    dprint('Doing training', id)

    # training_generator = DataGenerator(
    #     df=x_train[:int(len(x_train) * 0.9)], to_fit=True, batch_size=BATCH_SIZE, dim=exp_util.MAX_LENGTH, n_classes=2)
    # validation_generator = DataGenerator(df=x_train[int(len(x_train) * 0.9):], to_fit=True, batch_size=BATCH_SIZE,
    #                                        dim=exp_util.MAX_LENGTH, n_classes=2)
    training_generator = DataGenerator(
        df=x_train, to_fit=True, batch_size=BATCH_SIZE, dim=exp_util.MAX_LENGTH, n_classes=2)
    validation_generator = DataGenerator(df=df[df.index.isin(testing_packed_benign+testing_unpacked_benign+testing_unpacked_malicious+testing_packed_malicious)], to_fit=True, batch_size=32, dim=exp_util.MAX_LENGTH, n_classes=2, shuffle=False)
    model.fit_generator(generator=training_generator, validation_generator=validation_generator, epochs=EPOCHS)

    # temporarily store the size of the sets used
    stats = {'ratio_ben': ratio_ben * 100, 'ratio_mal': ratio_mal * 100,
            'training_packed_malicious': len(training_packed_malicious),
            'training_unpacked_benign': len(training_unpacked_benign),
            'training_packed_benign': len(training_packed_benign),
            'training_unpacked_malicious': len(training_unpacked_malicious),
            'testing_unpacked_malicious': len(testing_unpacked_malicious),
            'testing_packed_benign': len(testing_packed_benign),
            'testing_unpacked_benign': len(testing_unpacked_benign),
            'testing_packed_malicious': len(testing_packed_malicious)}
    dprint(stats)

    # evaluating on a dataset with same ratio as training dataset
    # print("evaluating on the test dataset with the same ratio as the training dataset")
    packed_test = df[df.index.isin(testing_packed_benign + testing_packed_malicious)]
    unpacked_test = df[df.index.isin(testing_unpacked_benign + testing_unpacked_malicious)]

    packed_test = packed_test.sample(frac=1)[:32*int(len(packed_test)/32)]
    unpacked_test = unpacked_test.sample(frac=1)[:32*int(len(unpacked_test)/32)]
    test = (packed_test, unpacked_test)

    results, conf = evaluate(model, test, stats, do_conf_score=(round==0))

    dprint('Done evaluating, returning:', id)
    model.save_model('{}/model-{}-{}-{}'.format(RES_DIR, ratio_ben, ratio_mal, round))
    return {'results': results, 'confidence': conf}


def evaluate(model, test, results, do_conf_score=False):
    """
    Evaluate the current trained model on a test dataset (via model_score function)
    Store results with appropriate resultClass
    :param test: pandas dataframe containing the dataset to test against
    :param resultObj: resultClass object for storing results
    :rtype: None
    """
    packed_test, unpacked_test = test

    tn_packed, fp_packed, fn_packed, tp_packed, packed_conf_dist            = model.model_score(packed_test)
    tn_unpacked, fp_unpacked, fn_unpacked, tp_unpacked, unpacked_conf_dist  = model.model_score(unpacked_test)

    fp = fp_packed + fp_unpacked
    tp = tp_packed + tp_unpacked
    tn = tn_packed + tn_unpacked
    fn = fn_packed + fn_unpacked

    results.update({'fn_packed': int(fn_packed), 'fn_unpacked': int(fn_unpacked),
            'tn_packed': int(tn_packed), 'tn_unpacked': int(tn_unpacked),
            'fp_packed': int(fp_packed), 'fp_unpacked': int(fp_unpacked),
            'tp_packed': int(tp_packed), 'tp_unpacked': int(tp_unpacked),
            'fn': int(fn), 'tn': int(tn), 'fp': int(fp), 'tp': int(tp)})
    conf_dist = None
    if do_conf_score:
        conf_dist = conf_dist_to_dict(packed_test, packed_conf_dist)
        conf_dist.update(conf_dist_to_dict(unpacked_test, unpacked_conf_dist))

    return results, conf_dist


def conf_dist_to_dict(x_list, c_list):
    '''
    Helper function that "formats" the confidence score
    to a format used in analysis by us
    @Hojjat, expand if needed
    '''
    assert len(x_list) == len(c_list)
    if not len(x_list):
        return {}

    conf_dist = {}
    c = 0
    for index, x in x_list.iterrows():
        conf_dist[index] = {'sha1': x['sample_sha1'], 'label': x['malicious'], 'packed': x['packed'], 'conf': float(max(c_list[c][0], c_list[c][1])), 'predict': int(np.argmax(c_list[c]))}
        c += 1
    return conf_dist


if __name__ == '__main__':
    main(conf_file=sys.argv[1])
