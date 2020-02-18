#!/bin/bash
db=$1
json=$1.json
csv=$1.csv
augcsv=$1.csv
python3 process_sql.py $db
python3 add_metrics_csv.py $csv $augcsv
