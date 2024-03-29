#!/usr/bin/env python3
import numpy as np
import traceback
import multiprocessing

# imports for rich
import richlibrary

import sys
sys.path.append('../../')
import util

def RichHeader(objpath):
    return richlibrary.RichLibrary(objpath)

def parse_richheader(filename):
    error = 0
    rich_parser = RichHeader(filename)

    try:
        rich = rich_parser.parse()
    except richlibrary.FileSizeError:
        error = -2
    except richlibrary.MZSignatureError:
        error = -3
    except richlibrary.MZPointerError:
        error = -4
    except richlibrary.PESignatureError:
        error = -5
    except richlibrary.RichSignatureError:
        error = -6
    except richlibrary.DanSSignatureError:
        error = -7
    except richlibrary.HeaderPaddingError:
        error = -8
    except richlibrary.RichLengthError:
        error = -9
    except Exception as e:
        print(traceback.format_exc(e))

    if error < 0:
        # print("\x1b[33m[-] " + richlibrary.err2str(error) + "\x1b[39m")
        return [0] * 66
    else:
        # rich_parser.pprint_header(rich)
        if len(rich) == 66:
            return rich
        else:
            return [0] * 66

def get_rich_names():
    rich_cols = ['offset', 'csum_calc', 'csum_file']
    for i in range(21):
        rich_cols.extend(['cnt_{}'.format(i), 'mcv_{}'.format(i), 'pid_{}'.format(i)])
    rich_cols = ['rich_{}'.format(r) for r in rich_cols]
    return rich_cols

def get_rich_features(data):
    try:
        index, packer_name, sample_sha1, src, unpacked_sample_sha1 = data

        sample_path = util.get_sample_path(src=src, sample_sha1=sample_sha1, unpacked_sample_sha1=unpacked_sample_sha1, packer_name=packer_name)
        return index, parse_richheader(sample_path)
    except Exception as e:
        print(e)
        print(src, packer_name, sample_sha1)
        return None, None

def collect_data(row):
    idx = row.name
    row = row.to_dict()
    packer_name             = row['packer_name']
    sample_sha1             = row['sample_sha1']
    src                     = row['source']
    unpacked_sample_sha1    = row['unpacked_sample_sha1']
    return [idx, packer_name, sample_sha1, src, unpacked_sample_sha1]

def collect_data_dfsplit(df):
    return df.apply(collect_data, axis=1)

def get_rich_features_for_all():

    df = util.load_wildlab_df()
    labels = [l for l in util.LABELS if l in df.columns]

    rich_cols = ['offset', 'csum_calc', 'csum_file']
    for i in range(21):
        rich_cols.extend(['cnt_{}'.format(i), 'mcv_{}'.format(i), 'pid_{}'.format(i)])
    rich_cols = ['rich_{}'.format(r) for r in rich_cols]
    rich_vals = [[] for i in range(len(rich_cols))]

    df['index'] = df.index
    cnt = len(df)
    print("need to extract rich header features for {} samples".format(cnt))
    with multiprocessing.Pool(multiprocessing.cpu_count()) as p:
        res = p.map(get_rich_features, np.array(df[['index', 'packer_name', 'sample_sha1', 'source', 'unpacked_sample_sha1']]))
    df.drop('index', axis=1, inplace=True)

    res = {index: richs for index, richs in res if index is not None}
    print("now making columns")
    for idx in df.index:
        if idx in res:
            richs = res[idx]
        else:
            richs = [0] * len(rich_cols)

        for i in range(len(richs)):
            rich_vals[i].append(richs[i])

        cnt -= 1
        if cnt % 1000 == 0:
            print("still {} samples remaining".format(cnt))

    cnt = len(rich_cols)
    print("now adding {} rich columns to the dataframe".format(cnt))
    for i in range(len(rich_cols)):
        col = rich_cols[i]
        vals = rich_vals[i]
        df[col] = vals
        cnt -= 1
        if cnt % 10:
            print("still {} columns remaining".format(cnt))

    import IPython
    IPython.embed()
    # util.save_wildlab_df(df)

if __name__ == '__main__':
    get_rich_features_for_all()
