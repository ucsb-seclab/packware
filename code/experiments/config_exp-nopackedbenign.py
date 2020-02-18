import itertools
import numpy as np
import exp_util

import sys
sys.path.append('../')
import util

ratio_step = 5
rounds = 5
# for the main program
iterations = list(itertools.product(*[[0], [1], range(rounds)]))
print(sys.argv)
model_name = sys.argv[2]
features = exp_util.get_features_ctgs(sys.argv[3:])

dataframe = util.load_wild_df()

res_dir = '{}/exp-noPackedBenign/{}/{}'.format(exp_util.RES_ROOT, model_name, '-'.join(sorted(features)))
util.make_dir(res_dir)
database = '{}/exp.db'.format(res_dir)

n_workers = 5
cores_per_worker = -1

def process_dataset(df, seed):
    '''
    Process the entire dataset just one time to save memory
    param df pandas dataframe
    :rtype: Tuple(pandas.dataframe)
    :return: The original arguments as a tuple and their concatenation
    '''

    # df = df[df.source.isin(util.WILD_SRC)]

    print("label encoding of strings features")
    df = exp_util.label_encode(df, res_dir)
    pb = df[df.benign][df.packed]
    upb = df[df.benign][~df.packed]
    pm = df[df.malicious]
    n = min(len(pm), len(upb))
    pm = pm.sample(n, random_state=seed)
    upb = upb.sample(n, random_state=seed)
    indices = list(pm.index) + list(upb.index) + list(pb.index)
    df = df[df.index.isin(indices)]
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
    training_packed_benign      = unpacked_malicious # empty
    training_unpacked_malicious = unpacked_malicious
    testing_packed_malicious    = unpacked_malicious
    testing_unpacked_benign     = unpacked_malicious
    testing_unpacked_malicious  = unpacked_malicious

    testing_packed_benign       = packed_benign
    training_unpacked_benign    = unpacked_benign
    training_packed_malicious   = packed_malicious

    return list(training_packed_benign.index), list(testing_packed_benign.index), list(training_unpacked_benign.index), list(testing_unpacked_benign.index), list(training_packed_malicious.index), list(testing_packed_malicious.index), list(training_unpacked_malicious.index), list(testing_unpacked_malicious.index)

