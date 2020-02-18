#!/bin/sh
python training.py config_exp-labagainstwild $1 lab-v3
cd ../results/
respath=../../results/paper/experiments/exp-labagainstwild/$1/lab-v3/dll-generic-header-import-ngrams-opcodes-rich-sections-strings
db=$respath/exp.db
json=$db.json
csv=$db.csv
python process_sql.py $db
python add_metrics_csv.py $csv $csv
python metrics.py $json
python top_features.py $json 50

cd $(dirname "$0")
