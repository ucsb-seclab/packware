#!/bin/sh
python training.py config_exp-bestclassifier.py $1
cd ../results
respath=../../results/paper/experiments/exp-bestClassifier/$1/dll-generic-header-import-ngrams-opcodes-rich-sections-strings
db=$respath/exp.db
json=$db.json
csv=$db.csv
augcsv=$db.csv
python process_sql.py $db
python add_metrics_csv.py $csv $augcsv
python top_features.py $json 50
python plot_scores.py $json

cd $(dirname "$0")
