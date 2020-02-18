import os
import sys
sys.path.append('../../')
import util
import json
import numpy as np
import multiprocessing
from sklearn.externals import joblib
from sklearn.preprocessing import LabelEncoder

def warn(*args, **kwargs):
    pass
import warnings
warnings.warn = warn

def adv_realSample(modelpath, samplepath, stringspath, featurespath, encoderspath):
    os.chdir('../../data/features')
    from extract_features import parse_pe
    os.chdir(os.path.dirname(__file__))
    global encoders
    encoders = load_encoders(encoderspath)
    clf = joblib.load(modelpath)
    res = parse_pe(samplepath)
    features = {'api_import_nb': len(res['imps']), 'dll_import_nb': len(res['dlls'])}
    strings = {}
    for ctg, feat in res.items():
        if type(feat) == list:
            feat = {f: 1 for f in feat}
        features.update(feat)
    with open(stringspath, 'r') as f:
        lines = f.readlines()
    for l in lines:
        assert l.endswith('\n')
        strings['string_{}'.format(l[:-1].encode())] = 1
    features.update(strings)

    model_features = util.read_json(featurespath)
    feature_names = model_features['features']
    vector = []
    for f in feature_names:
        if f in features:
            print(f)
            vector.append(features[f])
        elif f.startswith('pesection_') and '_name' in f:
            vector.append('none')
        else:
            vector.append(0)
    # vector = get_vector(vector, feature_names)
    import IPython
    IPython.embed()

def get_benign_features(features, weights, dfb, dfm):
    THR = 1
    TOP = 2000
    # path = 'benign-features-{}-{}.json'.format(THR, TOP)
    # if os.path.exists(path):
    #     print("reading benign features from json file")
    #     return util.read_json(path)
    res = []
    cnt = 0
    for f, w in zip(features, weights):
        if f.startswith('ngram_') or f.startswith('string_'):
            xb = dfb[[f]]
            xm = dfm[[f]]
            b_cnt = len(xb[xb[f]])
            m_cnt = len(xm[xm[f]])
            if m_cnt == 0:
                m_cnt = 1
            if b_cnt >= 100:
                # print(b_cnt / m_cnt)
                if (b_cnt / m_cnt) >= THR:
                    res.append([w, f, b_cnt, m_cnt])
        cnt += 1
        if cnt == TOP:
            break
    # util.write_json(path, res)
    res = sorted(res, key=lambda x: x[2]/x[3], reverse=True)
    return res

def adv_onlyOnePacker(modelpath, confspath, featurespath):
    global clf, benign_feature_names, features_df
    cur_dir = os.path.dirname(os.path.abspath(__file__))
    confspath = os.path.abspath(os.path.join(cur_dir, confspath))
    res = util.read_json(confspath)
    featurespath = os.path.abspath(os.path.join(cur_dir, featurespath))
    features = util.read_json(featurespath)
    features = [[w, f] for w, f in zip(features['weights'], features['features'])]
    features_sorted = sorted(features, reverse=True)
    feature_names_sorted = [f for _, f in features_sorted]
    feature_weights_sorted = [w for w, _ in features_sorted]
    clf = joblib.load(modelpath)
    assert res and clf
    confs = json.loads(res['0.5']['1.0']['confidence'])
    # feature_names = json.loads(json.loads(res['1.0']['1.0']['features']))
    malconfs = {id: val for id, val in confs.items() if val['label'] == 1 and val['predict'] == 1}
    lowconfs = {id: v for id, v in malconfs.items() if v['conf'] <= 0.6}
    global df, dfb, dfm
    df = util.load_wildlab_df()
    features_df = [f for f in df.columns if f in feature_names_sorted]
    # df = df[df.packer_name == packer]
    dfb = df[df.benign]
    dfm = df[df.malicious]
    benign_features = get_benign_features(feature_names_sorted, feature_weights_sorted, dfb, dfm)
    benign_feature_weights = [w for w, _, _, _ in benign_features]
    benign_feature_names = [f for _, f, _, _ in benign_features]

    data = []
    for sample_id, value in malconfs.items():
        cur_conf = confs[sample_id]['conf']
        data.append([sample_id, cur_conf])
    print("generating adv. samples for {} samples".format(len(data)))
    with multiprocessing.Pool() as p:
        res = p.map(attack, data)
    res = {sample_id: {'log': r, 'initConf': cur_conf, 'finalConf': final_conf, 'minChanges': min_changes, 'maxChanges': max_changes} for r, cur_conf, final_conf, sample_id, min_changes, max_changes in res}

    resdir = '../../../results/paper/experiments/exp-adversarial'
    if not os.path.exists(resdir):
        os.makedirs(resdir)
    with open('{}/malconfs-adv.json'.format(resdir), 'w') as f:
        json.dump(res, f)

def attack(data):
    sample_id, cur_conf = data
    conf_thr = 0.9
    sample_id = int(sample_id)
    x = df.loc[sample_id, features_df]
    vx = get_vector(x, features_df) 
    predict = clf.predict_proba(vx)
    prev_benign_score = predict[0][0]
    try:
        assert cur_conf == predict[0][1]
    except Exception as e:
        print(e)
    res = []
    y = x.copy(deep=True)
    min_changes = 0
    thr_changes = 0
    cnt = 0
    print("generating adv. samples from sample: {}".format(sample_id))
    for b in benign_feature_names:
        if y[b] == False: # the sample does not have the feature, so let's inject it
            y[b] = True
            vy = get_vector(y, features_df)
            benign_score = clf.predict_proba(vy)[0][0]
            inc = benign_score - prev_benign_score
            if inc > 0:
                # print("{}: injecting feature {} increased benign score from {} to {}".format(sample_id, b, prev_benign_score, benign_score))
                res.append({"inc": inc, 'feature': b})
                prev_benign_score = benign_score
                cnt += 1
                if benign_score >= 0.5 and min_changes == 0:
                    min_changes = cnt
                if benign_score >= conf_thr and thr_changes == 0:
                    thr_changes = cnt
            elif inc < 0:
                y[b] = False
            if benign_score >= conf_thr:
                print("adv. sample generated from sample: {}".format(sample_id))
                break
    return res, cur_conf, benign_score, sample_id, min_changes, thr_changes

def get_vector(inp, feature_names):
    v = []
    for x, f in zip(inp, feature_names):
        if x == np.NaN:
            v.append(0)
        if type(x) == str:
            assert 'name' in f
            v.append(encoders[f].transform([x])[0])
        else:
            v.append(x)
    return np.array(v).reshape(1, -1)

def load_encoders(path):
    encoders = {}
    for root, _, files in os.walk(path):
        for f in files:
            if f.endswith('-encoder.npy'):
                col = f.split('-encoder.npy')[0]
                encoder = LabelEncoder()
                encoder.classes_ = np.load(os.path.join(root, f))
                encoders[col] = encoder
    return encoders

if __name__ == '__main__':
    resultspath = sys.argv[1]
    modelpath = '{}/model-0.5-1.0.joblib'.format(resultspath)
    featurespath = '{}/features-0.5-1.0.json'.format(resultspath)
    confspath = '{}/exp.db.json'.format(resultspath)
    encoderspath = '{}/encoders/'.format(resultspath)
    global encoders
    encoders = load_encoders(encoderspath)
    adv_onlyOnePacker(modelpath, confspath, featurespath)
