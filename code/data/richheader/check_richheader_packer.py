import sys
sys.path.append('../../')
import util
import multiprocessing

def check_rich_features(sample):
    upid = sample['unpacked_sample_id']
    assert upid != -1
    org_richs = list(wild.loc[upid, richs])
    packed_richs = list(sample[richs])
    for x, y in zip(org_richs, packed_richs):
        if x != y:
            if y:
                return -1
            return 0
    return 1

def check_packer(packer):
    if packer == 'none':
        return
    # print(packer)
    dfp = df[df.packer_name == packer]
    print(packer, len(dfp), len(dfp[dfp.benign]), len(dfp[dfp.malicious]))
    # dfp = dfp.sample(frac=0.1)
    return packer, dfp[cols].apply(check_rich_features, axis=1)

def main(dataframe):
    global richs, labels, cols, wild, df
    df = dataframe
    wild = df[df.packer_name == 'none']
    richs = [c for c in df.columns if c.startswith('rich_')]
    labels = [c for c in util.LABELS if c in df.columns]
    cols = labels + richs
    with multiprocessing.Pool() as p:
        tmp = p.map(check_packer, list(df.packer_name.unique()))
    tmp = [t for t in tmp if t]
    for packer, res in tmp:
        print(packer, len([r for r in res if r == 1]), len([r for r in res if r == 0]), len([r for r in res if r == -1]))
    return tmp
if __name__ == '__main__':
    df = util.load_wildlab_df()
    try:
        res = main(df)
    except:
        pass
    import IPython
    IPython.embed()
