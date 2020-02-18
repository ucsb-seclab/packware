import os
import random
import subprocess
import pandas as pd
from itertools import combinations

packers = ['pecompact', 'pelock', 'themida-v2', 'obsidium', 'petite', 'mpress', 'telock', 'kkrunchy', 'upx']
random.shuffle(packers)
acc_max = .0
acc_min = 100.0
for comb in combinations(packers, 4):
    cmd = 'python training.py config_exp-goodbadpackers lab-v3 {}'.format(' '.join(comb))
    print(cmd)
    subprocess.check_call(cmd.split(" "))

for root, dirs, files in os.walk("../../results/paper/experiments/exp-goodbadpackers/lab-v3/"):
    for f in files:
        if f.endswith('.db'):
            expdbpath = os.path.join(root, f)
    
            cmd = 'python ../results/process_sql.py {}'.format(expdbpath)
            subprocess.check_call(cmd.split(" "))
            cmd = 'python ../results/add_metrics_csv.py {csvpath} {csvpath}'.format(csvpath='{}.csv'.format(expdbpath))
            subprocess.check_call(cmd.split(" "))

            csv = pd.read_csv('{}.csv'.format(expdbpath))
            acc_min = min(acc_min, csv['accuracy'].iloc[0])
            acc_max = max(acc_max, csv['accuracy'].iloc[0])

print('acc_min: {}, acc_max: {}'.format(acc_min, acc_max))
