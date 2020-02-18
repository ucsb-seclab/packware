from sklearn import preprocessing
RES_ROOT = '../../results/paper/experiments'
import numpy as np
import os
import sys
sys.path.append('../')
import util
DROP_COLUMNS = util.LABELS

def get_features_ctgs(dropped_ctg):
    ctgs = set(['import', 'sections', 'dll', 'rich', 'header', 'strings', 'generic', 'opcodes', 'ngrams'])
    for dctg in dropped_ctg:
        assert dctg in ctgs

    return list(ctgs - set(dropped_ctg))

def check_features_ctgs(incl_ctgs):
    ctgs = set(['import', 'sections', 'dll', 'rich', 'header', 'strings', 'generic', 'opcodes', 'ngrams'])
    for ctg in incl_ctgs:
        assert ctg in ctgs
    if len(incl_ctgs):
        return incl_ctgs
    else:
        return list(ctgs)

def label_encode(df, res_dir):
    for col in df.columns:
        if col in DROP_COLUMNS:
            continue
        dtype = df[col].dtype
        if dtype == object:
            # print("label encoding of column: {}".format(col))
            le = preprocessing.LabelEncoder()
            df[col] = le.fit_transform(df[col])
            save_encoder(le, col, res_dir)
    return df

def save_encoder(le, col, res_dir):
    try:
        if not os.path.exists('{}/encoders/'.format(res_dir)):
            os.makedirs('{}/encoders/'.format(res_dir))
    except Exception as e:
        print(e)
    np.save('{}/encoders/{}-encoder.npy'.format(res_dir, col), le.classes_)

def balance_per_packer(df, seed, packers=None, minsize=None):
    if packers == None:
        packers = [p for p in df.packer_name.unique() if p != 'none']
    indices = list(df[df.packed == 0].index)

    packed_benign = df[(df.benign == 1) & (df.packed == 1)]
    packed_malicious = df[(df.benign == 0) & (df.packed == 1)]

    b = packed_benign['packer_name'].value_counts()
    m = packed_malicious['packer_name'].value_counts()

    cur_min = 100000
    for p in packers:
        if p not in b or p not in m:
            continue
        n = min(b[p], m[p])
        print("packer {}, benign: {}, malicious: {}".format(p, b[p], m[p]))
        if n == 0:
            print("WARNING: packer {} is out of training".format(p))
            continue
        cur_min = min(cur_min, n)

    if minsize:
        cur_min = min(cur_min, minsize)
    print(cur_min)

    for p in packers:
        pb = packed_benign[packed_benign.packer_name == p]
        pm = packed_malicious[packed_malicious.packer_name == p]
        n = min(pb.shape[0], pm.shape[0])
        if n == 0:
            continue
        indices.extend(list(pb.sample(cur_min, random_state=seed).index))
        indices.extend(list(pm.sample(cur_min, random_state=seed).index))

    return df[df.index.isin(indices)]

def balance_each_packer(df, seed, packers=None):
    if packers == None:
        packers = [p for p in df.packer_name.unique() if p != 'none']
    indices = list(df[df.packed == 0].index)

    packed_benign = df[(df.benign == 1) & (df.packed == 1)]
    packed_malicious = df[(df.benign == 0) & (df.packed == 1)]

    for p in packers:
        pb = packed_benign[packed_benign.packer_name == p]
        pm = packed_malicious[packed_malicious.packer_name == p]
        n = min(pb.shape[0], pm.shape[0])
        print("packer {}, benign: {}, malicious: {}".format(p, pb.shape[0], pm.shape[0]))
        if n == 0:
            print("WARNING: packer {} is out of training".format(p))
            continue
        pb = pb.sample(n, random_state=seed)
        pm = pm.sample(n, random_state=seed)

        indices.extend(list(pb.index))
        indices.extend(list(pm.index))

    return df[df.index.isin(indices)]


def balance_sets(df, seed, mode):

    # divide between malicious/benign, packed/unpacked
    packed_benign = df[(df.benign == 1) & (df.packed == 1)].index.to_frame()
    unpacked_benign = df[(df.benign == 1) & (df.packed == 0)].index.to_frame()
    packed_malicious = df[(df.benign == 0) & (df.packed == 1)].index.to_frame()
    unpacked_malicious = df[(df.benign == 0) & (df.packed == 0)].index.to_frame()
    print('Packed benign:', packed_benign.shape[0])
    print('Unpacked benign:', unpacked_benign.shape[0])
    print('Packed malicious:', packed_malicious.shape[0])
    print('Unpacked malicious:', unpacked_malicious.shape[0])
    print('balancing')

    if mode == 0:
        # reduce to min number
        n = min(packed_benign.shape[0], unpacked_benign.shape[0], int(packed_malicious.shape[0] / 2))
        packed_benign = packed_benign.sample(n, random_state=seed)
        unpacked_benign = unpacked_benign.sample(n, random_state=seed)
        packed_malicious = packed_malicious.sample(2*n, random_state=seed)
        # unpacked_malicious = unpacked_malicious.sample(n, random_state=seed)
        print('Packed benign:', packed_benign.shape[0])
        print('Unpacked benign:', unpacked_benign.shape[0])
        print('Packed malicious:', packed_malicious.shape[0])
        print('Unpacked malicious:', unpacked_malicious.shape[0])
    elif mode == 1:
        # reduce to min number
        n = min(packed_benign.shape[0], unpacked_benign.shape[0], packed_malicious.shape[0])
        packed_benign = packed_benign.sample(n, random_state=seed)
        unpacked_benign = unpacked_benign.sample(n, random_state=seed)
        packed_malicious = packed_malicious.sample(n, random_state=seed)
        # unpacked_malicious = unpacked_malicious.sample(n, random_state=seed)
        print('Packed benign:', packed_benign.shape[0])
        print('Unpacked benign:', unpacked_benign.shape[0])
        print('Packed malicious:', packed_malicious.shape[0])
        print('Unpacked malicious:', unpacked_malicious.shape[0])


    indices = list(packed_benign.index) + list(unpacked_benign.index) + list(packed_malicious.index) + list(unpacked_malicious.index)

    df = df[df.index.isin(indices)]

    return df

def divide_set(df, train_r, train_pac_r, test_pac_r, seed):
    '''
    Split a dataset into training and testing depending on the values of the config file and ratio parameter
    :param train_r: ratio for train/test sets
    :param train_pac_r: ratio for packed/unpacked in the train set
    :param test_pac_r: ratio for packed/unpacked in the test set
    :param seed: seed for random state when shuffling
    :return: tuple of (training set, test set)
    :rtype: Tuple
    '''
    if len(df) == 0:
        return df, df
    df = df.sample(random_state=seed, frac=1)
    n = df.shape[0]
    train = df[:round(n*train_r)]
    test = df[round(n*train_r):]
    nn = test.shape[0]
    test = test[:round(nn * test_pac_r)]
    nn = train.shape[0]
    train = train[:round(nn * train_pac_r)]
    return train, test

def divide_dataset(indices, ratio_ben, ratio_mal, seed, sizes):
    packed_benign, unpacked_benign, packed_malicious, unpacked_malicious = indices

    # split between test, train
    training_packed_benign, testing_packed_benign           = divide_set(packed_benign, sizes['training_ratio'], ratio_ben, sizes['testing_packed_benign_ratio'], seed)
    training_unpacked_benign, testing_unpacked_benign       = divide_set(unpacked_benign, sizes['training_ratio'], 1 - ratio_ben, 1 - sizes['testing_packed_benign_ratio'], seed)
    training_packed_malicious, testing_packed_malicious     = divide_set(packed_malicious, sizes['training_ratio'], ratio_mal, sizes['testing_packed_malicious_ratio'], seed)
    training_unpacked_malicious, testing_unpacked_malicious = divide_set(unpacked_malicious, sizes['training_ratio'], 1 - ratio_mal, 1 - sizes['testing_packed_malicious_ratio'], seed)
    return list(training_packed_benign.index), list(testing_packed_benign.index), list(training_unpacked_benign.index), list(testing_unpacked_benign.index), list(training_packed_malicious.index), list(testing_packed_malicious.index), list(training_unpacked_malicious.index), list(testing_unpacked_malicious.index)
    # return training_packed_benign, testing_packed_benign, training_unpacked_benign, testing_unpacked_benign, training_packed_malicious, testing_packed_malicious, training_unpacked_malicious, testing_unpacked_malicious

MAX_LENGTH = int(1e6) # look at the plots/fileSize-wildlab.pdf, basically we ignore 2,269 samples from all 426,116 samples in the wildlab dataset!!!

def remove_large_samples(df):
    prev_size = len(df)
    df = df[df['generic_fileSize'] <= MAX_LENGTH]
    print("considering samples with size less than {} bytes, {} ----> {}".format(MAX_LENGTH, prev_size, len(df)))
    return df

def import_bytes(df):
    assert len(df[df['generic_fileSize'] > MAX_LENGTH]) == 0
    df = add_content_bytes(df)

    return df

def add_content_bytes(df):
    df['content'] = 'none'
    print("reading samples in bytes and adding to the dataframe")
    res = df.apply(read_content, axis=1)
    df['content'] = res
    print("dataframe for the neural network now is ready")
    return df

def read_content(row):
    '''
    Read a pandas dataframe
    '''
    def right_pad(x):
        r = np.zeros(MAX_LENGTH)
        r[:len(x)] = x
        return r

    sample = row.to_dict()
    path = util.get_sample_path(src=sample['source'], sample_sha1=sample['sample_sha1'], unpacked_sample_sha1=sample['unpacked_sample_sha1'], packer_name=sample['packer_name'])
    with open(path, 'rb') as f:
        data = f.read()
    data = right_pad(bytearray(data))
    return np.asarray(data)
