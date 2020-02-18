import itertools
import numpy as np
import exp_util

import sys
sys.path.append('../')
import util

rounds = 5
# for the main program
iterations = list(itertools.product(*[[0.5], [1], range(rounds)]))
model_name = 'rf'
features = exp_util.get_features_ctgs(sys.argv[4:])

if 'strings' in features:
    dataframe = util.load_wildlab_df(nocorrupted=False, noduplicate=True, vtagree=True, dpiagree=False, strings=True)
else:
    dataframe = util.load_wildlab_df(nocorrupted=False, noduplicate=True, vtagree=True, dpiagree=False, strings=False)

if features == 'all' or ['all'] == features:
    res_dir = '{}/exp-all/all'.format(exp_util.RES_ROOT)
else:
    res_dir = '{}/exp-all/{}'.format(exp_util.RES_ROOT, '-'.join(sorted(features)))
util.make_dir(res_dir)
database = '{}/exp.db'.format(res_dir)

n_workers = 1
cores_per_worker = -1
max_depth = int(sys.argv[2])
n_trees = int(sys.argv[3])

sizes = dict(
    training_ratio = 0.7,
)

def process_dataset(df, seed):
    '''
    Process the entire dataset just one time to save memory
    param df pandas dataframe
    :rtype: Tuple(pandas.dataframe)
    :return: The original arguments as a tuple and their concatenation
    '''

    wild = df[df.source.isin(util.WILD_SRC)]
    wildb = wild[wild.benign]
    wildm = wild[wild.malicious]
    n = min(len(wildb), len(wildm))
    wildb = wildb.sample(n, random_state=seed)
    wildm = wildm.sample(n, random_state=seed)
    indices = list(wildb.index) + list(wildm.index)
    del wild
    del wildb
    del wildm
    import gc
    gc.collect()

    dfp = df[df.source == 'lab-v3']
    dfp = exp_util.balance_per_packer(dfp, seed)
    indices.extend(list(dfp.index))
    del dfp
    gc.collect()
    df = df[df.index.isin(indices)]

    print("label encoding of strings features")
    df = exp_util.label_encode(df)

    # df = exp_util.balance_four_sets(df, seed)

    # df = df.astype(np.float32, errors='ignore')

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
    train_r = sizes['training_ratio']
    training_packed_benign, testing_packed_benign = divide_set(packed_benign, train_r, seed)
    training_unpacked_benign, testing_unpacked_benign = divide_set(unpacked_benign, train_r, seed)
    training_packed_malicious, testing_packed_malicious = divide_set(packed_malicious, train_r, seed)
    training_unpacked_malicious, testing_unpacked_malicious = divide_set(unpacked_malicious, train_r, seed)

    return list(training_packed_benign.index), list(testing_packed_benign.index), list(training_unpacked_benign.index), list(testing_unpacked_benign.index), list(training_packed_malicious.index), list(testing_packed_malicious.index), list(training_unpacked_malicious.index), list(testing_unpacked_malicious.index)

