#!/bin/sh

# training on all features
python training.py config_exp-dolphin $1

# training on all features except generic
python training.py config_exp-dolphin $1 generic

cd ../results/

for r in dll-generic-header-import-ngrams-opcodes-rich-sections-strings dll-header-import-ngrams-opcodes-rich-sections-strings
do
    packer=dolphin-dropper-3
    echo PACKER $packer
    respath=../../results/paper/experiments/exp-dolphin/$1/dolphin-dropper-3/$r
    db=$respath/exp.db
    json=$db.json
    csv=$db.csv
    python process_sql.py $db
    python add_metrics_csv.py $csv $csv
    python metrics.py $json
    python top_features.py $json 50
    echo DONE WITH ANALYZING results of $packer
done

cd $(dirname "$0")
