import json
import sys
sys.path.append('../')
import util
import ast
from features import select_features_based_ctg, CTGS

def print_top_features(res_path, num):
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
            # THR = sum(weights) / (len(weights) * 1.0) # mean
            THR = 0
            ratios.append('ratio: {}, ratio2: {}'.format(ratio, ratio2))
            # import math
            # s = 0
            # for w in weights:
            #     s += w * w
            # a = math.sqrt(s)
            # print(sum(weights)/a)
            nonzero = [[w, f] for w,f in zip(weights, features) if w > THR]
            nonzerofeatures = [f for _, f in nonzero]
            nonzeroweights = [w for w,_ in nonzero]
            ctgs_nonzerofeatures = select_features_based_ctg(nonzeroweights, nonzerofeatures)
            ctgs_nonzerofeatures = {c: len(v['features']) for c, v in ctgs_nonzerofeatures.items()}
            top_features.append('\n'.join(['{} :{}'.format(round(w, 6), f) for w,f in sorted(zip(weights, features), reverse=True)[:num]]))
            features = [f for _,f in sorted(zip(weights, features), reverse=True)[:num]]
            weights = [w for w,_ in sorted(zip(weights, features), reverse=True)[:num]]
            ctgs_features = select_features_based_ctg(weights, features)
            ctgs_features = {c: len(v['features']) for c, v in ctgs_features.items()}
            # print(THR)
            print(ctgs_features)
            latex.append(' & '.join(['{} ({})'.format(ctgs_nonzerofeatures[ctg], ctgs_features[ctg]) for ctg in CTGS]))

    for ratio, top_features_ratio in zip(ratios, top_features):
        print(ratio)
        print(top_features_ratio)
        print("-------")
    print("************** FOR LATEX TABLE ***************")
    for ratio, l in zip(ratios, latex):
        print(ratio)
        print(l)
        print("-------")


if __name__ == '__main__':
    print_top_features(sys.argv[1], int(sys.argv[2]))
