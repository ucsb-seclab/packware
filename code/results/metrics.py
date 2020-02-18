import sys
sys.path.append('../')
import util
import sys
import json
from sklearn.metrics import f1_score, roc_auc_score

def compute_metrics(respath):
    res = util.read_json(respath)
    for ratio_b in sorted(res.keys()):
        res2 = res[ratio_b]
        for ratio_m in sorted(res2.keys()):
            r = res2[ratio_m]
            confs = json.loads(r['confidence'])
            values = [[val['predict'], val['label']] for _, val in confs.items()]
            predicts = [p for p, _ in values]
            labels = [l for _, l in values]
            f1 = f1_score(labels, predicts)
            roc_auc = roc_auc_score(labels, predicts)
            print('ratio_b: {}, ratio_m: {} ---> f1_score: {}, roc_auc: {}'.format(ratio_b, ratio_m, f1, roc_auc))

if __name__ == '__main__':
    assert len(sys.argv) > 1
    respath = sys.argv[1]
    compute_metrics(respath)
