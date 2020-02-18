#!/bin/sh
trainPacker=pecompact-petite-telock-themida-upx
packer=pelock
python training.py config_exp-packerVsPacker $1 $trainPacker $packer

cd ../results/
for packer in petite obsidium
do
    echo evaluating on $packer
    respath=../../results/paper/experiments/exp-packervspacker/$1/$trainPacker-vs-$packer/dll-generic-header-import-ngrams-opcodes-rich-sections-strings
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
