import sys
import pandas as pd

def ratios(input, output):
    d = pd.read_csv(input)
    # if 'fp_ratio_packed' in d.columns:
    #     print('fp_ratio: {}, fn_ratio: {}'.format(d['fp_ratio'].iloc[0], d['fn_ratio'].iloc[0]))
    #     return
    d['fp_ratio_packed']        = d['false positive for packed'] / (d['false positive for packed'] + d['true negative for packed'])
    d['fp_ratio_unpacked']      = d['false positive for unpacked'] / (d['false positive for unpacked'] + d['true negative for unpacked'])
    d['fn_ratio_packed']        = d['false negative for packed'] / (d['false negative for packed'] + d['true positive for packed'])
    d['fn_ratio_unpacked']      = d['false negative for unpacked'] / (d['false negative for unpacked'] + d['true positive for unpacked'])
    d['fp_ratio']               = d['false positive'] / (d['false positive'] + d['true negative'])
    d['fn_ratio']               = d['false negative'] / (d['false negative'] + d['true positive'])
    d['accuracy']               = (d['true positive'] + d['true negative']) / (d['true positive'] + d['true negative'] + d['false negative'] + d['false positive'])
    d['accuracy_packed']        = (d['true positive for packed'] + d['true negative for packed']) / (d['true positive for packed'] + d['true negative for packed'] + d['false negative for packed'] + d['false positive for packed'])
    d['accuracy_unpacked']      = (d['true positive for unpacked'] + d['true negative for unpacked']) / (d['true positive for unpacked'] + d['true negative for unpacked'] + d['false negative for unpacked'] + d['false positive for unpacked'])
    d['error_rate']             = 1.0 - d['accuracy']
    d['error_rate_packed']      = 1.0 - d['accuracy_packed']
    d['error_rate_unpacked']    = 1.0 - d['accuracy_unpacked']
    
    print("******** FALSE POSITIVE NEGATIVE RATES FOR ALL CASES ********")
    for idx, row in d.iterrows():
        row = row.to_dict()
        print('ratio_b: {}, ratio_m: {}'.format(row['packed benign ratio %'], row['packed malicious ratio %']))
        print('fp_ratio: {}, fp_ratio_packed: {}, fp_ratio_unpacked: {}'.format(row['fp_ratio'], row['fp_ratio_packed'], row['fp_ratio_unpacked']))
        print('fn_ratio: {}'.format(row['fn_ratio']))
        print('acc: {}'.format(row['accuracy']))
        print("--------")
    d.to_csv(output)
    return [row['accuracy'], row['fp_ratio'], row['fn_ratio']]

if __name__ == '__main__':
    ratios(sys.argv[1], sys.argv[1])
