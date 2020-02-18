#!/bin/sh
cl=$1
python training.py config_exp-nopackedbenign-evalall $cl
cd ../results/
respath=../../results/paper/experiments/exp-noPackedBenign/$cl/dll-generic-header-import-ngrams-opcodes-rich-sections-strings
db=$respath/exp.db
json=$db.json
csv=$db.csv
augcsv=$db.csv
python process_sql.py $db
python add_metrics_csv.py $csv $augcsv
python top_features.py $json 50
cd $(dirname "$0")
