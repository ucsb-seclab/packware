import itertools
import numpy as np
import exp_util

import sys
sys.path.append('../')
import util
src = sys.argv[3]
packers = [sys.argv[4]]

MAX_LENGTH = exp_util.MAX_LENGTH

rounds = 5
ratios = [1.0]
# for the main program
iterations = list(itertools.product(*[ratios, ratios, range(rounds)]))
model_name = sys.argv[2]
features = sys.argv[5:]
features = exp_util.check_features_ctgs(features)
# features = exp_util.get_features_ctgs(sys.argv[4:])
dataframe = util.load_wildlab_df()

dataframe = dataframe[dataframe.packer_name.isin(packers)]
# packers = ['dolphin-dropper']

if features == 'all' or ['all'] == features:
    res_dir = '{}/exp-singlePacker/{}/{}/{}/all'.format(exp_util.RES_ROOT, model_name, src, '-'.join(packers))
else:
    res_dir = '{}/exp-singlePacker/{}/{}/{}/{}'.format(exp_util.RES_ROOT, model_name, src, '-'.join(packers), '-'.join(sorted(features)))
util.make_dir(res_dir)
database = '{}/exp.db'.format(res_dir)

n_workers = 1
cores_per_worker = -1

sizes = dict(
    training_ratio = 0.7,
    testing_packed_malicious_ratio = 1,
    testing_packed_benign_ratio = 1
)


def process_dataset(df, seed):
    '''
    Process the entire dataset just one time to save memory
    param df pandas dataframe
    :rtype: Tuple(pandas.dataframe)
    :return: The original arguments as a tuple and their concatenation
    '''

    # df = df[df.source == src]
    # df = df[df.header_characteristics_bit13 == False]
    print("label encoding of strings features")
    df = exp_util.label_encode(df, res_dir)


    # df = exp_util.balance_four_sets(df, seed)
    if model_name == 'nn':
        # print("balancing per packer")
        cols = exp_util.DROP_COLUMNS + ['generic_fileSize']
        cols = [c for c in cols if c in df.columns]
        df = df[cols]
        df = exp_util.remove_large_samples(df)
        df = exp_util.balance_per_packer(df, seed, packers, minsize=4000)
        df = exp_util.import_bytes(df)
        df = df.drop(['generic_fileSize'], axis=1)
    else:
        # print("balancing per packer")
        df = exp_util.balance_per_packer(df, seed, packers)
        df = df.astype(np.float32, errors='ignore')

    return df

def divide_dataset(*args):
    return exp_util.divide_dataset(*args, sizes=sizes)
