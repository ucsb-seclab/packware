import itertools
import exp_util

import sys
sys.path.append('../')
import util

rounds = 5
# for the main program
iterations = list(itertools.product(*[[1.0], [1.0], range(rounds)]))
model_name = sys.argv[2]
features = sys.argv[5:]
features = exp_util.get_features_ctgs(features)

train_packer = sys.argv[3].split("-")
test_packer = sys.argv[4].split("-")
packers = []
packers.extend(train_packer)
packers.extend(test_packer)

dataframe = util.load_wildlab_df()

if features == 'all' or ['all'] == features:
    res_dir = '{}/exp-packervspacker/{}/{}-vs-{}/all'.format(exp_util.RES_ROOT, model_name,
                                                             sys.argv[2], sys.argv[3])
else:
    res_dir = '{}/exp-packervspacker/{}/{}-vs-{}/{}'.format(exp_util.RES_ROOT, model_name,
                                                            sys.argv[2], sys.argv[3], '-'.join(sorted(features)))
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

    # wild = df[df.source.isin(util.WILD_SRC)]

    # wildb = wild[wild.benign]
    # wildm = wild[wild.malicious]
    # n = min(len(wildb), len(wildm))
    # wildb = wildb.sample(n, random_state=seed)
    # wildm = wildm.sample(n, random_state=seed)
    # wild = wild[wild.index.isin(list(wildb.index) + list(wildm.index))]
    # global train_indices
    # train_indices = set(wild.index)
    # del wild
    # del wildb
    # del wildm
    # import gc
    # gc.collect()
    for p in packers:
        assert p in df.packer_name.unique()
    df = df[df.packer_name.isin(packers)]

    df = exp_util.balance_per_packer(df, seed)
    global test_indices, train_indices
    train_indices = set(df[df.packer_name.isin(train_packer)].index)
    test_indices = set(df[df.packer_name.isin(test_packer)].index)
    indices = train_indices.union(test_indices)

    df = df[df.index.isin(indices)]

    print("label encoding of strings features")
    df = exp_util.label_encode(df, res_dir)

    print("converting to float")
    import numpy as np
    df = df.astype(np.float32, errors='ignore', copy=False)
    print("done with converting")

    return df


def divide_dataset(indices, ratio_ben, ratio_mal, seed):
    packed_benign, unpacked_benign, packed_malicious, unpacked_malicious = indices

    training_packed_benign = packed_benign[packed_benign.index.isin(train_indices)]
    training_packed_malicious = packed_malicious[packed_malicious.index.isin(train_indices)]
    testing_packed_benign       = packed_benign[packed_benign.index.isin(test_indices)]
    testing_packed_malicious    = packed_malicious[packed_malicious.index.isin(test_indices)]


    assert len(testing_packed_benign) == len(testing_packed_malicious)
    assert len(training_packed_benign) == len(training_packed_malicious)

    testing_unpacked_malicious  = unpacked_malicious
    training_unpacked_malicious = unpacked_malicious
    testing_unpacked_benign     = unpacked_benign
    training_unpacked_benign    = unpacked_benign

    assert len(training_unpacked_malicious) == len(testing_unpacked_benign) == len(testing_unpacked_malicious) == len(training_unpacked_benign) == 0

    return list(training_packed_benign.index), list(testing_packed_benign.index), list(training_unpacked_benign.index), list(testing_unpacked_benign.index), list(training_packed_malicious.index), list(testing_packed_malicious.index), list(training_unpacked_malicious.index), list(testing_unpacked_malicious.index)

