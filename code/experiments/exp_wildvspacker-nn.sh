#!/bin/sh

for packer in pelock pecompact obsidium petite telock themida-v2 mpress kkrunchy upx
do
    echo PACKER $packer
    python training-nn.py config_exp-wildvspacker nn lab-v3 $packer
    echo DONE WITH TRAINING/TESTING of $packer
done

cd ../results/
for packer in pelock pecompact obsidium petite telock themida-v2 mpress kkrunchy upx
do
    echo PACKER $packer
    respath=../../results/paper/experiments/exp-wildvspacker/nn/lab-v3/$packer
    db=$respath/exp.db
    json=$db.json
    csv=$db.csv
    python process_sql.py $db
    python add_metrics_csv.py $csv $csv
    python metrics.py $json
    echo DONE WITH ANALYZING results of $packer
done

cd $(dirname "$1")
