import os
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.ticker as mtick
import pandas as pd
import sys

METRICS = ['fp_ratio_packed', 'fp_ratio_unpacked', 'fn_ratio_packed', 'fn_ratio_unpacked', 'fp_ratio', 'fn_ratio']
METRICS_SELECTED = ['fp_ratio', 'fp_ratio_packed', 'fn_ratio']
METRICS_LABELS = {'fp_ratio_packed': 'False Positive Rate for Packed Excutables', 'fp_ratio_unpacked': 'False Positive Rate for Unpacked Executables', 'fn_ratio_packed': 'False Negative Rate for Packed Executables', 'fn_ratio_unpacked': 'False Negative Rate for Unpacked Executables', 'fp_ratio': 'False Positive Rate', 'fn_ratio': 'False Negative Rate', 'error_rate': 'Error Rate', 'error_rate_packed': 'Error Rate for Packed Executables', 'error_rate_unpacked': 'Error Rate for Unpacked Executables', 'accuracy': 'Accuracy'}
METRICS_SHORT_LABELS = {'fp_ratio_packed': 'FP Rate (packed)', 'fp_ratio_unpacked': 'FP Rate (unpacked)', 'fn_ratio_packed': 'FN Rate (packed)', 'fn_ratio_unpacked': 'FN Rate (unpacked)', 'fp_ratio': 'FP Rate', 'fn_ratio': 'FN Rate', 'error_rate': 'Error Rate', 'error_rate_packed': 'Error Rate', 'error_rate_unpacked': 'Error Rate', 'accuracy': 'Accuracy'}
METRICS_COLORS = {'fp_ratio': 'crimson', 'fn_ratio': 'orange', 'fp_ratio_packed': 'black', 'fn_ratio_packed': 'gray'}
METRICS_LINE_STYLES = {'fp_ratio': '-', 'fn_ratio': '--', 'fp_ratio_packed': ':', 'fn_ratio_packed': '-.'}

CSV_HEADERS = ['packed benign ratio %', 'packed malicious ratio %',
                 '# training packed malicious', '# training unpacked malicious',
                 '# training packed benign', '# training unpacked benign',
                 '# testing packed malicious', '# testing unpacked malicious',
                 '# testing packed benign', '# testing unpacked benign',
                 'false negative for packed', 'false negative for unpacked',
                 'true negative for packed', 'true negative for unpacked',
                 'false positive for packed', 'false positive for unpacked',
                 'true positive for packed', 'true positive for unpacked',
                 'false negative', 'true negative',  'false positive', 'true positive']

def ratio_plot_diffpackedbenign(filepath):
    plots_path = os.path.dirname(filepath)
    data = pd.read_csv(filepath)
    plt.figure(figsize=(10, 6), dpi=300)
    ax = plt.subplot(111)
    FONTSIZE = 36
    ax.tick_params(axis='both', labelsize=FONTSIZE)
    # ax.set_xlabel('Ratio of Packed Benign in the Training Set', fontsize=FONTSIZE)

    for metric in METRICS_SELECTED:
        x = data[CSV_HEADERS[0]]
        y = data[metric]
        y = [round(v * 100) for v in y]
        ax.plot(x, y, label=METRICS_SHORT_LABELS[metric], color=METRICS_COLORS[metric], linestyle=METRICS_LINE_STYLES[metric], linewidth=4)

    ax.grid(color='black', linestyle='dotted', linewidth=0.1)
    ax.set_ylim([0, 100])

    tick = mtick.FormatStrFormatter('%d%%')
    ax.xaxis.set_major_formatter(tick)
    ax.yaxis.set_major_formatter(tick)

    # ax.legend(loc="upper right", fancybox=True, framealpha=0.5, fontsize=9)
    plt.savefig('{}/lab-diff-packed-benign-ratio-plot.pdf'.format(plots_path), bbox_inches='tight')
    plt.close()

if __name__ == '__main__':
    if len(sys.argv) > 1:
        filepath = sys.argv[1]
        ratio_plot_diffpackedbenign(filepath)
