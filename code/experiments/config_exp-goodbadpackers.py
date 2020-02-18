import itertools
import numpy as np
import exp_util
import os
import sys
sys.path.append('../')
import util

compute_conf_score = False

rounds = 1
# for the main program
iterations = list(itertools.product(*[[1.0], [1.0], range(rounds)]))
model_name = sys.argv[2]
# features = exp_util.get_features_ctgs(sys.argv[4:])
# src = sys.argv[2]
# packer = sys.argv[3]
features = exp_util.get_features_ctgs([])
src = sys.argv[3]
good_packers = sys.argv[4:]

dataframe = util.load_wildlab_df()

res_dir = '{}/exp-goodbadpackers/{}/{}/{}/{}'.format(exp_util.RES_ROOT, model_name,
                                                     src, '-'.join(sorted(good_packers)), '-'.join(sorted(features)))
print(res_dir)
util.make_dir(res_dir)
database = '{}/exp.db'.format(res_dir)
if os.path.isfile(database):
    import sys
    sys.exit(0)

n_workers = 1
cores_per_worker = -1

def process_dataset(df, seed):
    '''
    Process the entire dataset just one time to save memory
    param df pandas dataframe
    :rtype: Tuple(pandas.dataframe)
    :return: The original arguments as a tuple and their concatenation
    '''

    df = df[df.source == src]
    df = exp_util.balance_per_packer(df, seed)
    all_packers = df.packer_name.unique()
    for gp in good_packers:
        assert gp in all_packers
    good_df = df[df.packer_name.isin(good_packers)]
    bad_df = df[~df.packer_name.isin(good_packers)]
    good_df_b = good_df[good_df.benign]
    good_df_m = good_df[good_df.malicious]
    bad_df_b = bad_df[bad_df.benign]
    bad_df_m = bad_df[bad_df.malicious]

    del good_df, bad_df
    import gc
    gc.collect()

    global train_indices, test_indices
    # training set = good_df_b + bad_df_m ---- keep in mind that we want a balanced training set, so:
    n = min(len(good_df_b), len(bad_df_m))
    good_df_b = good_df_b.sample(n, random_state=seed)
    bad_df_m = bad_df_m.sample(n, random_state=seed)
    train_indices = set(good_df_b.index).union(set(bad_df_m.index))
    del good_df_b, bad_df_m
    gc.collect()

    # test set = good_df_m + bad_df_b ---- keep in mind that we want a balanced test set also, so:
    n = min(len(good_df_m), len(bad_df_b))
    good_df_m = good_df_m.sample(n, random_state=seed)
    bad_df_b = bad_df_b.sample(n, random_state=seed)
    test_indices = set(good_df_m.index).union(set(bad_df_b.index))
    del good_df_m, bad_df_b
    gc.collect()

    indices = train_indices.union(set(test_indices))

    df = df[df.index.isin(indices)]
    
    print("label encoding of strings features")
    df = exp_util.label_encode(df, res_dir)

    df = df.astype(np.float32, errors='ignore')
    print("done with converting to float")
    return df


def divide_dataset(indices, ratio_ben, ratio_mal, seed):
    packed_benign, unpacked_benign, packed_malicious, unpacked_malicious = indices

    training_packed_benign = packed_benign[packed_benign.index.isin(train_indices)]
    training_packed_malicious = packed_malicious[packed_malicious.index.isin(train_indices)]
    testing_packed_benign       = packed_benign[packed_benign.index.isin(test_indices)]
    testing_packed_malicious    = packed_malicious[packed_malicious.index.isin(test_indices)]

    assert len(testing_packed_benign) == len(testing_packed_malicious)
    assert len(training_packed_benign) == len(training_packed_malicious)

    training_unpacked_benign    = unpacked_benign
    training_unpacked_malicious = unpacked_malicious
    testing_unpacked_benign     = unpacked_benign
    testing_unpacked_malicious  = unpacked_malicious

    assert len(training_unpacked_malicious) == len(testing_unpacked_benign) == len(testing_unpacked_malicious) == len(training_unpacked_benign) == 0

    return list(training_packed_benign.index), list(testing_packed_benign.index), list(training_unpacked_benign.index), list(testing_unpacked_benign.index), list(training_packed_malicious.index), list(testing_packed_malicious.index), list(training_unpacked_malicious.index), list(testing_unpacked_malicious.index)

