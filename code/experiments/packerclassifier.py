import sys
sys.path.append('../')
import util
# from sklearn import preprocessing
from sklearn.externals import joblib
import os
import pandas as pd
import json
import sklearn
import sklearn.ensemble
import exp_util
SEED = 17
DROP_COLUMNS = ['sample_sha1', 'unpacked_sample_sha1', 'unpacked_sample_id', 'packed', 'packer_name', 'source', 'benign', 'malicious', 'similarity', 'benign_vt', 'malicious_vt', 'dpi_cmpx', 'corrupted', 'most_similar_sha1', 'unpacked_similarity']

def balance_per_packer(df, seed=SEED):
    indices = []
    packers = df.packer_name.unique()
    cur_min = 100000
    for p in packers:
        if p == 'none':
            continue
        dp = df[df.packer_name == p]
        cur_min = min(cur_min, len(dp))

    print(cur_min)

    for p in packers:
        if p == 'none':
            continue
        dp = df[df.packer_name == p]
        indices.extend(list(dp.sample(cur_min, random_state=seed).index))

    return df[df.index.isin(indices)]

def load_data(respath):
    df = util.load_wildlab_df()
    df = balance_per_packer(df)

    global packer_codes
    packer_codes = {}
    i = 0
    for p in sorted(list(df.packer_name.unique())):
        i += 1
        packer_codes[p] = i
    df['packer_name'] = [packer_codes[p] for p in df['packer_name']]
    df = exp_util.label_encode(df, respath)
    l = len(df)
    train_l = int(l * 0.7)
    train_x = df.sample(train_l, random_state=SEED)
    test_x = df[~df.index.isin(train_x.index)]
    test_y = test_x['packer_name']
    train_y = train_x['packer_name']
    train_x = train_x.drop(columns=DROP_COLUMNS, axis=1, errors='ignore')
    test_x = test_x.drop(columns=DROP_COLUMNS, axis=1, errors='ignore')

    return train_x, train_y, test_x, test_y

def get_model(n_jobs):
    return sklearn.ensemble.RandomForestClassifier(n_estimators=100, n_jobs=n_jobs, random_state=SEED)

def main(respath):
    if not os.path.exists(respath):
        os.makedirs(respath)
    train_x, train_y, test_x, test_y = load_data(respath)
    assert len(train_x) == len(train_y)
    assert len(test_x) == len(test_y)
    print('training size: {}'.format(len(train_x)))
    print('test size: {}'.format(len(test_x)))

    model = get_model(n_jobs=-1)

    print("now training")
    model.fit(train_x, train_y)

    print("now testing")
    pred = model.predict(test_x)

    print(pd.crosstab(test_y, pred))

    feature_imp = {f: i for f, i in zip(train_x.columns, model.feature_importances_)}
    with open('{}/features.json'.format(respath), 'w') as f:
        json.dump(feature_imp, f)
    joblib.dump(model, '{}/model.pkl'.format(respath)) 

    import IPython
    IPython.embed()


def conf_matrix(respath):
    import IPython
    IPython.embed()

if __name__ == '__main__':
    main(sys.argv[1])
    # conf_matrix(sys.argv[1])
