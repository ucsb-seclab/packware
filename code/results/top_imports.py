import json
import sys
sys.path.append('../')
import util
import ast

def get_top_features(res_path, num):
    res = util.read_json(res_path)
    latex = []
    ratios = []
    top_features = []
    for ratio in sorted(res.keys()):
        for ratio2 in sorted(res[ratio].keys()):
            weights = json.loads(res[ratio][ratio2]['weights'])
            weights = ast.literal_eval(weights)
            features = json.loads(res[ratio][ratio2]['features'])
            features = ast.literal_eval(features)
            features = [f for _,f in sorted(zip(weights, features), reverse=True)[:num]]
            weights = [w for w,_ in sorted(zip(weights, features), reverse=True)[:num]]

    return features


def get_common_features():
    from collections import Counter
    features = Counter()
    packers = []
    for p in util.PACKERS:
        if p in ['none', 'dolphin-dropper-3', 'themida-v2', 'telock', 'kkrunchy']:
            continue
        packers += [p]
        respath = '../../results/paper/experiments/exp-singlePacker/rf/lab-v3/{}/import/exp.db.json'.format(p)
        tmp = get_top_features(respath, 50)
        for t in tmp:
            features[t] += 1
    features = features.most_common(11)
    features = [f for f, _ in features if f != 'api_import_nb']
    
    df = util.load_wildlab_df()
    cols = util.LABELS
    cols = [d for d in df.columns if d.startswith('imp_') or d in cols]
    df = df[cols]
    print(packers)
    for f in features:
        latex = '{} & '.format(f)
        for p in packers:
            dp = df[df.packer_name == p]
            db = dp[dp.benign]
            dm = dp[dp.malicious]
            x = len(db[db[f]])
            y = len(dm[dm[f]])
            latex += '\\textbf{' + str(x) + ' (' + str(round((x*100.0)/len(db), 2)) + '\%)} & \\textbf{' + str(y) + ' (' + str(round((y*100.0)/len(dm), 2)) + '\%)} & '
        latex = latex[:-3] + " \\\\"
        print(latex)

if __name__ == '__main__':
    get_common_features()
