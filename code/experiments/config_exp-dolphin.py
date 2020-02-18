import itertools
import numpy as np
import exp_util

import sys
sys.path.append('../')
import util
packer = 'dolphin-dropper-3'

rounds = 5
ratios = [1.0]
# for the main program
iterations = list(itertools.product(*[ratios, ratios, range(rounds)]))
model_name = sys.argv[2]
features = exp_util.get_features_ctgs(sys.argv[3:])
dataframe = util.load_wildlab_df()

dataframe = dataframe[dataframe.packer_name == packer]
# packers = ['dolphin-dropper']

if features == 'all' or ['all'] == features:
    res_dir = '{}/exp-dolphin/{}/{}/all'.format(exp_util.RES_ROOT, model_name, packer)
else:
    res_dir = '{}/exp-dolphin/{}/{}/{}'.format(exp_util.RES_ROOT, model_name, packer, '-'.join(sorted(features)))
util.make_dir(res_dir)
database = '{}/exp.db'.format(res_dir)

n_workers = 5
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

    print("label encoding of strings features")
    df = exp_util.label_encode(df, res_dir)

    # print("balancing per packer")
    df = exp_util.balance_per_packer(df, seed, [packer])

    df = df.astype(np.float32, errors='ignore')

    return df

def divide_dataset(*args):
    return exp_util.divide_dataset(*args, sizes=sizes)
