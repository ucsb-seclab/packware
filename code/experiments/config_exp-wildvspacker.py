import itertools
import numpy as np
import exp_util

import sys
sys.path.append('../')
import util

rounds = 5
# for the main program
iterations = list(itertools.product(*[[0.5], [1], range(rounds)]))
model_name = sys.argv[2]
features = sys.argv[5:]
if len(features):
    exp_util.check_features_ctgs(features)
else:
    features = exp_util.get_features_ctgs(features)
src = sys.argv[3]
packer = sys.argv[4]

dataframe = util.load_wildlab_df()

if model_name == 'nn':
    columns = [c for c in util.LABELS if c in dataframe.columns]
    dataframe = dataframe[columns]
    res_dir = '{}/exp-wildvspacker/{}/{}/{}'.format(exp_util.RES_ROOT, model_name, src, packer)
elif features == 'all' or ['all'] == features:
    res_dir = '{}/exp-wildvspacker/{}/{}/{}/all'.format(exp_util.RES_ROOT, model_name, src, packer)
else:
    res_dir = '{}/exp-wildvspacker/{}/{}/{}/{}'.format(exp_util.RES_ROOT,
                                                       model_name, src, packer, '-'.join(sorted(features)))
util.make_dir(res_dir)
database = '{}/exp.db'.format(res_dir)

n_workers = 100
cores_per_worker = -1
if model_name == 'nn':
    n_workers = 1

def process_dataset(df, seed):
    '''
    Process the entire dataset just one time to save memory
    param df pandas dataframe
    :rtype: Tuple(pandas.dataframe)
    :return: The original arguments as a tuple and their concatenation
    '''

    wild = df[df.source.isin(util.WILD_SRC)]
    wild = exp_util.balance_sets(wild, seed, mode=1)

    global dfp
    dfp = df[df.packer_name == packer]
    # dfp = exp_util.balance_per_packer(dfp, seed, [packer])

    global train_indices
    train_indices = set(wild.index)
    test_indices = set(dfp.index)
    indices = train_indices.union(test_indices)
    df = df[df.index.isin(indices)]

    print("label encoding of strings features")
    df = exp_util.label_encode(df, res_dir)

    df = df.astype(np.float32, errors='ignore')

    return df


def divide_dataset(indices, ratio_ben, ratio_mal, seed):
    packed_benign, unpacked_benign, packed_malicious, unpacked_malicious = indices

    training_packed_benign, _ = exp_util.divide_set(packed_benign[packed_benign.index.isin(train_indices)], 1, ratio_ben, 0, seed)
    training_unpacked_benign, testing_unpacked_benign = exp_util.divide_set(unpacked_benign, 1, 1 - ratio_ben, 0, seed)
    training_packed_malicious, _ = exp_util.divide_set(packed_malicious[packed_malicious.index.isin(train_indices)], 1, ratio_mal, 0, seed)
    training_unpacked_malicious, testing_unpacked_malicious = exp_util.divide_set(unpacked_malicious, 1, 1 - ratio_mal, 0, seed)

    train_indices_now = list(training_packed_benign.index) + list(training_unpacked_benign.index) + list(training_packed_malicious.index) + list(training_unpacked_malicious.index)
    testing_packed = dfp[dfp.unpacked_sample_id.isin(train_indices_now)]
    testing_packed_benign = testing_packed[testing_packed.benign].index.to_frame()
    testing_packed_malicious = testing_packed[testing_packed.malicious].index.to_frame()

    n = min(len(testing_packed_benign), len(testing_packed_malicious))
    testing_packed_benign = testing_packed_benign.sample(n, random_state=seed)
    testing_packed_malicious = testing_packed_malicious.sample(n, random_state=seed)

    return list(training_packed_benign.index), list(testing_packed_benign.index), list(training_unpacked_benign.index), list(testing_unpacked_benign.index), list(training_packed_malicious.index), list(testing_packed_malicious.index), list(training_unpacked_malicious.index), list(testing_unpacked_malicious.index)

