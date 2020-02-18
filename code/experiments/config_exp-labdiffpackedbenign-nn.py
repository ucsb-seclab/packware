import itertools
import numpy as np
import exp_util

import sys
sys.path.append('../')
import util

ratio_step = 10
rounds = 5
ratios = [r/100 for r in range(0, 100+ratio_step, ratio_step)]
# for the main program
iterations = list(itertools.product(*[ratios, [1.0], range(rounds)]))[:11]
model_name = 'nn'

dataframe = util.load_wildlab_df()
columns = [c for c in util.LABELS if c in dataframe.columns]
dataframe = dataframe[columns]
res_dir = '{}/exp-labDiffPackedBenign/{}'.format(exp_util.RES_ROOT, model_name)

util.make_dir(res_dir)
database = '{}/exp.db'.format(res_dir)

n_workers = 1
cores_per_worker = -1

sizes = dict(
    training_ratio = 0.7,
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

    # df = df[df.source.isin(util.WILD_SRC)]
    packers = list(df.packer_name.unique())
    packers = [p for p in packers if p != 'none']
    df = exp_util.balance_per_packer(df, seed, packers)

    print("label encoding of strings features")
    df = exp_util.label_encode(df, res_dir)

    df = exp_util.balance_sets(df, seed, mode=1)

    df = df.astype(np.float32, errors='ignore')

    return df

def divide_dataset(indices, ratio_ben, ratio_mal, seed):
    packed_benign, unpacked_benign, packed_malicious, unpacked_malicious = indices
    assert len(unpacked_malicious) == 0
    training_packed_benign, testing_packed_benign           = exp_util.divide_set(packed_benign, sizes['training_ratio'], ratio_ben, sizes['testing_packed_benign_ratio'], seed)
    training_unpacked_benign, testing_unpacked_benign       = exp_util.divide_set(unpacked_benign, sizes['training_ratio'], 1 - ratio_ben, 1 - sizes['testing_packed_benign_ratio'], seed)
    training_packed_malicious, testing_packed_malicious     = exp_util.divide_set(packed_malicious, sizes['training_ratio'], ratio_mal, sizes['testing_packed_malicious_ratio'], seed)
    training_unpacked_malicious = unpacked_malicious
    testing_unpacked_malicious  = unpacked_malicious

    return list(training_packed_benign.index), list(testing_packed_benign.index), list(training_unpacked_benign.index), list(testing_unpacked_benign.index), list(training_packed_malicious.index), list(testing_packed_malicious.index), list(training_unpacked_malicious.index), list(testing_unpacked_malicious.index)

