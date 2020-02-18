#!/bin/sh
python training-nn.py config_exp-diffpackedbenign-nn
cd ../results/
respath=../../results/paper/experiments/exp-diffPackedBenign/nn
db=$respath/exp.db
json=$db.json
csv=$db.csv
python process_sql.py $db
python add_metrics_csv.py $csv $csv
python plot_diffpackedbenign.py $csv
cd $(dirname "$0")
