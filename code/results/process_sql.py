import sqlite3
import csv
import json as json
import sys
import os
'''
this script is used to process a sqlite3 database
that contains the results of one experiment

Usage:
    python3 process_sql.py path/to/db
'''


def best_res(d1, d2):
    """
    Return best resutls among different rounds, for Neural Network.
    """
    assert len(d1)
    tp1 = d1['tp']
    fp1 = d1['fp']
    fn1 = d1['fn']
    tn1 = d1['tn']
    acc1 = (tp1*1.0 + tn1) / (tp1 + tn1 + fn1 + fp1)

    tp2 = d2['tp']
    fp2 = d2['fp']
    fn2 = d2['fn']
    tn2 = d2['tn']
    acc2 = (tp2*1.0 + tn2) / (tp2 + tn2 + fn2 + fp2)

    if acc2 > acc1:
        return d2
    else:
        return d1

def add(d1, d2):
    '''
    add results of two different dictionaries
    '''
    assert len(d1)
    for k, v in d2.items():
        d1[k] = d1[k] + v
    return d1



# connect to db
assert os.path.exists(sys.argv[1])
conn = sqlite3.connect(sys.argv[1])
conn.row_factory = sqlite3.Row
c = conn.cursor()
# c.execute('select * from results limit 2')
c.execute('select * from results')
result = c.fetchall()


final = dict() # store average results and weight + features + confidences of round 0

# iterate rows
for row in result:
    row = dict(row)
    assert len(row)
    ratio_ben = row['ratio_ben']
    ratio_mal = row['ratio_mal']
    round = row['round']
    row['results'] = json.loads(row['results'])
    print('processing row:', ratio_ben, ratio_mal, round)
    if ratio_ben not in final:
        final[ratio_ben] = {ratio_mal: {'results': row['results'], 'round_cnt': 1}}
    else:
        if ratio_mal not in final[ratio_ben]:
            final[ratio_ben][ratio_mal] = {'results': row['results'], 'round_cnt': 1}
        else:
            # final[ratio_ben][ratio_mal]['results'] = best_res(final[ratio_ben][ratio_mal]['results'], row['results'])
            final[ratio_ben][ratio_mal]['results'] = add(final[ratio_ben][ratio_mal]['results'], row['results'])
            final[ratio_ben][ratio_mal]['round_cnt'] += 1
    if round == 0:
        final[ratio_ben][ratio_mal]['confidence'] = row['confidence']
        final[ratio_ben][ratio_mal]['weights'] = row['weights']
        final[ratio_ben][ratio_mal]['features'] = row['features']

# average
for ratio_ben in final:
    for ratio_mal in final[ratio_ben]:
        round_cnt = final[ratio_ben][ratio_mal]['round_cnt']
        final[ratio_ben][ratio_mal]['results'] = {k: v/round_cnt for k, v in final[ratio_ben][ratio_mal]['results'].items()}

with open(sys.argv[1] + '.json', 'w') as f:
    # store the json file
    f.write(json.dumps(final))


def write_csv(filename, final):
    '''
    function to generate csv file
    '''
    csv_path = filename + '.csv'

    with open(csv_path, 'w') as fp:
        csv_w = csv.writer(fp)
        csv_w.writerow(['packed benign ratio %', 'packed malicious ratio %',
            '# training packed malicious', '# training unpacked malicious',
            '# training packed benign', '# training unpacked benign',
            '# testing packed malicious', '# testing unpacked malicious',
            '# testing packed benign', '# testing unpacked benign',
            'false negative for packed', 'false negative for unpacked',
            'true negative for packed', 'true negative for unpacked',
            'false positive for packed', 'false positive for unpacked',
            'true positive for packed', 'true positive for unpacked',
            'false negative', 'true negative',  'false positive', 'true positive'])
    with open(csv_path, 'a') as f:
        csv_w = csv.writer(f)
        for i in sorted(final.keys()):
            for j in sorted(final[i].keys()):
                results = final[i][j]['results']
                csv_w.writerow([results['ratio_ben'], results['ratio_mal'],
                                results['training_packed_malicious'],
                                results['training_unpacked_malicious'],
                                results['training_packed_benign'], results['training_unpacked_benign'],
                                results['testing_packed_malicious'],
                                results['testing_unpacked_malicious'],
                                results['testing_packed_benign'], results['testing_unpacked_benign'],
                                results['fn_packed'], results['fn_unpacked'],
                                results['tn_packed'], results['tn_unpacked'],
                                results['fp_packed'], results['fp_unpacked'],
                                results['tp_packed'], results['tp_unpacked'],
                                results['fn'], results['tn'], results['fp'],
                                results['tp']])

# write the csv using the above function
write_csv(sys.argv[1], final)
