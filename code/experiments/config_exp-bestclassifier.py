import itertools
import numpy as np
import exp_util

import sys
sys.path.append('../')
import util

rounds = 5
# for the main program
iterations = list(itertools.product(*[[0.5], [1.0], range(rounds)]))
model_name = sys.argv[2]
features = exp_util.get_features_ctgs(sys.argv[3:])

dataframe = util.load_wildlab_df()

if features == 'all' or ['all'] == features:
    res_dir = '{}/exp-bestClassifier/{}/all'.format(exp_util.RES_ROOT, model_name)
else:
    res_dir = '{}/exp-bestClassifier/{}/{}'.format(exp_util.RES_ROOT, model_name, '-'.join(sorted(features)))
import os
util.make_dir(res_dir)
database = '{}/exp.db'.format(res_dir)
if os.path.exists(database):
    sys.exit(1)

n_workers = 5
cores_per_worker = -1

sizes = dict(
    training_ratio = 0.9,
    testing_packed_benign_ratio = 0.5,
    testing_packed_malicious_ratio = 1
)

def process_dataset(df, seed):
    '''
    Process the entire dataset just one time to save memory
    param df pandas dataframe
    :rtype: Tuple(pandas.dataframe)
    :return: The original arguments as a tuple and their concatenation
    '''

    df = df[df.packer_name != 'dolphin-dropper-3']
    # df = df[df.source.isin(util.WILD_SRC)]
    packers = list(df.packer_name.unique())
    packers = [p for p in packers if p != 'none']

    indices = set(exp_util.balance_per_packer(df[df.packer_name.isin(packers)], seed, packers).index)
    indices = indices.union(set(df[df.packer_name == 'none'].index))
    df = df[df.index.isin(indices)]

    print("label encoding of strings features")
    df = exp_util.label_encode(df, res_dir)

    df = exp_util.balance_sets(df, seed, mode=0)

    df = df.astype(np.float32, errors='ignore')

    return df

def divide_set(df, train_r, seed):
    if len(df) == 0:
        return df, df
    df = df.sample(random_state=seed, frac=1)
    n = df.shape[0]
    train = df[:round(n*train_r)]
    test = df[round(n*train_r):]
    return train, test

def divide_dataset(indices, ratio_ben, ratio_mal, seed):
    packed_benign, unpacked_benign, packed_malicious, unpacked_malicious = indices
    assert len(unpacked_malicious) == 0
    training_packed_benign, testing_packed_benign           = divide_set(packed_benign, sizes['training_ratio'], seed)
    training_unpacked_benign, testing_unpacked_benign       = divide_set(unpacked_benign, sizes['training_ratio'], seed)
    training_packed_malicious, testing_packed_malicious     = divide_set(packed_malicious, sizes['training_ratio'], seed)
    training_unpacked_malicious = unpacked_malicious
    testing_unpacked_malicious  = unpacked_malicious

    return list(training_packed_benign.index), list(testing_packed_benign.index), list(training_unpacked_benign.index), list(testing_unpacked_benign.index), list(training_packed_malicious.index), list(testing_packed_malicious.index), list(training_unpacked_malicious.index), list(testing_unpacked_malicious.index)

