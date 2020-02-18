import os
import json
import shutil
import hashlib
import pandas as pd

LABELS = ['sample_sha1', 'unpacked_sample_sha1', 'unpacked_sample_id', 'packed', 'packer_name', 'source', 'benign',
          'malicious', 'similarity', 'benign_vt', 'malicious_vt', 'dpi_cmpx', 'corrupted', 'most_similar_sha1',
          'unpacked_similarity', 'packed_static_manalyze']
PACKERS = ['dolphin-dropper-3', 'obsidium', 'themida-v2', 'petite', 'telock', 'kkrunchy', 'upx', 'mpress', 'pelock',
           'pecompact']
WILD_SRC = ['wild', 'wild-ember']
LAB_SRC = ['lab-v3', 'lab-dropper']


def get_sample_path(src=None, sample_sha1=None, unpacked_sample_sha1=None, packer_name=None):
    cur_dir = os.path.dirname(os.path.abspath(__file__))
    if not src:
        assert sample_sha1
        for src in WILD_SRC:
            rel = '../../{}/samples/{}/{}.bin'.format(src, '/'.join(sample_sha1[:3]), sample_sha1)
            path = os.path.abspath(os.path.join(cur_dir, rel))
            if os.path.exists(path):
                return path

    elif src in WILD_SRC:
        assert sample_sha1
        rel = '../../{}/samples/{}/{}.bin'.format(src, '/'.join(sample_sha1[:3]), sample_sha1)
    elif src == 'lab-v1':
        rel = '../../new-packed-lab/samples/{}/packed/{}.{}.bin'.format(packer_name, unpacked_sample_sha1, packer_name)
    elif src == 'lab-v2':
        rel = '../../new-packed-lab/samples2/{}/packed/{}.{}.bin'.format(packer_name, unpacked_sample_sha1, packer_name)
    elif src == 'lab-v3':
        rel = '../../new-packed-lab/samples3/{}/packed/{}.{}.bin'.format(packer_name, unpacked_sample_sha1, packer_name)
        path = os.path.abspath(os.path.join(cur_dir, rel))
        if not os.path.exists(path):
            rel = '../../new-packed-lab/samples3/{}/packed/{}/{}.{}.bin'.format(packer_name,
                                                                                '/'.join(unpacked_sample_sha1[:3]),
                                                                                unpacked_sample_sha1, packer_name)
            path = os.path.abspath(os.path.join(cur_dir, rel))
        return path
    elif src == 'lab-dropper':
        rel = '../../dropper-lab/samples/{}/packed/{}/{}.{}.bin'.format(packer_name, '/'.join(unpacked_sample_sha1[:3]),
                                                                        unpacked_sample_sha1, packer_name)
    else:
        assert False

    return os.path.abspath(os.path.join(cur_dir, rel))


def read_sample(src=None, sample_sha1=None, unpacked_sample_sha1=None, packer_name=None):
    sample_path = get_sample_path(src=src, sample_sha1=sample_sha1, unpacked_sample_sha1=unpacked_sample_sha1,
                                  packer_name=packer_name)
    assert os.path.exists(sample_path)
    with open(sample_path, 'rb') as f:
        return f.read()


def make_dir(dir_path):
    if dir_path != '' and not os.path.exists(dir_path):
        try:
            os.makedirs(dir_path)
        except Exception as e:
            print(e)


'''
utilities in the form of small functions.
'''


def write_json(filepath, data):
    '''
    Convenience method for writing to a json
    :param filepath: string of the filename
    :param data: Data to be written as json
    '''
    with open(filepath, 'w') as f:
        json.dump(data, f)


def read_json(filepath):
    '''
    Convenience method for reading from a json
    :param filepath: string of the filename
    :return: Data read from json
    '''
    if os.path.isfile(filepath):
        with open(filepath) as f:
            return json.load(f)
    else:
        return None


def compute_sha1(filepath):
    sha1sum = hashlib.sha1()
    with open(filepath, 'rb') as source:
        block = source.read(2 ** 16)
        while len(block) != 0:
            sha1sum.update(block)
            block = source.read(2 ** 16)
    return sha1sum.hexdigest()


def load_wild_df(light=False):
    cur_dir = os.path.dirname(os.path.abspath(__file__))
    df_path = '../data/wild.pickle'
    df_path = os.path.abspath(os.path.join(cur_dir, df_path))

    if os.path.exists(df_path):
        df = pd.read_pickle(df_path)
        if light:
            labels = [l for l in LABELS if l in df.columns]
            df = df[labels]
        return df
    else:
        return None


def save_wild_df(df):
    cur_dir = os.path.dirname(os.path.abspath(__file__))
    df_path = '../data/wild.pickle'
    df_path = os.path.abspath(os.path.join(cur_dir, df_path))

    df.to_pickle(df_path)


def load_wildlab_df(light=False):
    cur_dir = os.path.dirname(os.path.abspath(__file__))
    df_path = '../data/wildlab.pickle'
    df_path = os.path.abspath(os.path.join(cur_dir, df_path))

    if os.path.isfile(df_path):
        df = pd.read_pickle(df_path)
        if light:
            labels = [l for l in LABELS if l in df.columns]
            df = df[labels]
        return df
    else:
        return None


def save_wildlab_df(df, strings=False):
    cur_dir = os.path.dirname(os.path.abspath(__file__))

    if strings:
        df_path = '../data/pefile/wildlab-strings.pickle'
    else:
        df_path = '../data/pefile/wildlab.pickle'
    df_path = os.path.abspath(os.path.join(cur_dir, df_path))

    df.to_pickle(df_path)


def get_valid_samples(df, valid_sample_ids):
    valid_sample_ids = valid_sample_ids.union(
        set(df[(~df.source.isin(WILD_SRC)) & (df.unpacked_sample_id.isin(valid_sample_ids))].index))
    df = df[df.index.isin(valid_sample_ids)]
    return df


def get_virustotal_report(src, sample_sha1):
    cur_dir = os.path.dirname(os.path.abspath(__file__))
    if src == 'wild':
        rel = "../../vt_reports/vt_reports_2018-08-20/{}.vt.json".format(sample_sha1)
    elif src == 'wild-ember':
        rel = "../../vt_reports/vt_reports_ember_2018-11-19/{}.vt.json".format(sample_sha1)
    elif src == 'lab-v3':
        rel = "../../vt_reports/lab-v3_2019-2-8/{}.vt.json".format(sample_sha1)
    path = os.path.abspath(os.path.join(cur_dir, rel))
    return read_json(path)


def save_virustotal_report(src, sample_sha1, data):
    cur_dir = os.path.dirname(os.path.abspath(__file__))
    if src == 'lab-v3':
        rel = "../../vt_reports/lab-v3_2019-2-8/{}.vt.json".format(sample_sha1)
    path = os.path.abspath(os.path.join(cur_dir, rel))
    write_json(path, data)


def get_sha1s(src):
    if src in WILD_SRC:
        df = load_wild_df(light=True)
    else:
        df = load_wildlab_df(light=True)
    df = df[df.source == src]
    return list(df['sample_sha1'])


def make_dir_for_file(filepath):
    dirpath = '/'.join(filepath.split('/')[:-1])
    make_dir(dirpath)


def load_clusters_json(srcs, packers, desc):
    assert type(srcs) == list
    if packers:
        assert type(packers) == list
    else:
        packers = []
    cur_dir = os.path.dirname(os.path.abspath(__file__))
    rel = '../data/clusters/{}/{}/clusters_{}.json'.format(desc, '-'.join(srcs), '-'.join(packers))
    path = os.path.abspath(os.path.join(cur_dir, rel))
    assert os.path.exists(path)

    return read_json(path)


def save_clusters_json(srcs, packers, desc, data):
    assert type(srcs) == list
    if packers:
        assert type(packers) == list
    else:
        packers = []
    cur_dir = os.path.dirname(os.path.abspath(__file__))
    rel = '../data/clusters/{}/{}/clusters_{}.json'.format(desc, '-'.join(srcs), '-'.join(packers))
    path = os.path.abspath(os.path.join(cur_dir, rel))
    make_dir_for_file(path)
    write_json(path, data)


# plots

def get_plotpath_unpackedSimilarityScore(src, packer_name):
    cur_dir = os.path.dirname(os.path.abspath(__file__))
    rel = '../results/data/unpacked_similarity_scores/{}/unpacked_similarity_score-{}.pdf'.format(src, packer_name)
    return os.path.abspath(os.path.join(cur_dir, rel))
