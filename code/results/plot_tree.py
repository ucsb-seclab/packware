import sys
import ast
import json
from sklearn.externals import joblib
from sklearn.tree import export_graphviz

sys.path.append('../')
import util

def load_model(model_path):
    return joblib.load(model_path)


def plot_tree(res_path):
    scores_path = '{}/exp.db.json'.format(res_path)
    res = util.read_json(scores_path)
    for ratio in sorted(res.keys()):
        for ratio2 in sorted(res[ratio].keys()):
            
            features = json.loads(res[ratio][ratio2]['features'])
            features = ast.literal_eval(features)
            model_path = '{}/model-{}-{}.joblib'.format(res_path, ratio, ratio2)
            model = load_model(model_path)
            # Extract single tree
            idx = 0
            for estimator in model.estimators_[:10]:
                idx += 1

                out_file = '{}/trees/tree-{}-{}-tree-{}.dot'.format(res_path, ratio, ratio2, idx)
                out_file_png = '{}/trees/tree-{}-{}-tree-{}.png'.format(res_path, ratio, ratio2, idx)
                util.make_dir_for_file(out_file)
                # Export as dot file
                export_graphviz(estimator, out_file=out_file, 
                                class_names=['benign', 'malicious'],
                                rounded=True, filled=True, proportion=True, feature_names=features)

                # Convert to png using system command (requires Graphviz)
                from subprocess import call
                call(['dot', '-Tpng', out_file, '-o', out_file_png, '-Gdpi=600'])

if __name__ == '__main__':
    plot_tree(sys.argv[1])
