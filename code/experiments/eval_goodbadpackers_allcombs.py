import os
import subprocess
from itertools import combinations

packers = ['pecompact', 'pelock', 'themida-v2', 'obsidium', 'petite', 'mpress', 'telock', 'kkrunchy', 'upx']

import sys
sys.path.append("../results")
from add_metrics_csv import ratios
model_name = sys.argv[1]

os.chdir("../results")
stats = []
for comb in combinations(packers, 4):
    respath = '../../results/paper/experiments/exp-goodbadpackers/' \
              '{}/lab-v3/{}/dll-generic-header-import-ngrams-opcodes-rich-sections-strings'\
        .format(model_name, '-'.join(sorted(comb)))
    if os.path.exists('{}/exp.db'.format(respath)):
        print("GOOD PACKERS: {}".format('-'.join(sorted(comb))))
        cmd1 = 'python process_sql.py {}/exp.db'.format(respath)
        # cmd2 = 'python add_metrics_csv.py {}/exp.db.csv {}/exp.db.csv'.format(respath, respath)
        # cmd3 = 'python top_features.py {}/exp.db.json 50'.format(respath)

        for cmd in [cmd1]:
            # print(cmd)
            subprocess.check_call(cmd.split(" "))
        stats.append(ratios('{}/exp.db.csv'.format(respath), '{}/exp.db.csv'.format(respath)))
        print("++++++++++++++++++++++++++++++++++")

print("min acc: {}".format(min([s[0] for s in stats])))
print("max acc: {}".format(max([s[0] for s in stats])))
print("min fp: {}".format(min([s[1] for s in stats])))
print("max fp: {}".format(max([s[1] for s in stats])))
print("min fn: {}".format(min([s[2] for s in stats])))
print("max fn: {}".format(max([s[2] for s in stats])))
