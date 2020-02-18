import exp_util
import subprocess
import itertools

features = exp_util.get_features_ctgs([])
for l in range(1, len(features)):
    for comb in itertools.combinations(features, l):
        cmd = 'python training.py config_exp-bestclassifier {}'.format(' '.join(comb))
        subprocess.call(cmd, shell=True)
