import os
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import sys
sys.path.append('../')
import util
import json

def get_mean(l):
    return round((sum(l) * 1.0) / len(l), 2)

def scores_box_plot(res_path):
    res = util.read_json(res_path)
    for ratio in sorted(res.keys()):
        for ratio2 in sorted(res[ratio].keys()):
            scores = res[ratio][ratio2]['confidence']
            scores = json.loads(scores)
            # import IPython
            # IPython.embed()
            fp_packed_scores = [v['conf'] for k, v in scores.items() if v['packed'] and not v['label'] and v['predict']]
            fp_unpacked_scores =  [v['conf'] for k, v in scores.items() if not v['packed'] and not v['label'] and v['predict']]
            tn_packed_scores =  [v['conf'] for k, v in scores.items() if v['packed'] and not v['label'] and not v['predict']]
            tn_unpacked_scores =  [v['conf'] for k, v in scores.items() if not v['packed'] and not v['label'] and not v['predict']]
            tp_packed_scores =  [v['conf'] for k, v in scores.items() if v['packed'] and v['label'] and v['predict']]
            fn_packed_scores =  [v['conf'] for k, v in scores.items() if v['packed'] and v['label'] and not v['predict']]


            t_packed_scores = [v['conf'] for k, v in scores.items() if v['packed'] and v['label'] == v['predict']]
            f_packed_scores = [v['conf'] for k, v in scores.items() if v['packed'] and v['label'] != v['predict']]
            t_unpacked_scores = [v['conf'] for k, v in scores.items() if not v['packed'] and v['label'] == v['predict']]
            f_unpacked_scores = [v['conf'] for k, v in scores.items() if not v['packed'] and v['label'] != v['predict']]
            # xlabels = ['False positives (packed samples)', 'False positives (unpacked samples)', 'True negatives (packed samples)', 'True negatives (unpacked samples)', 'True positives (packed samples)', 'False negatives (packed samples)', 'Correctly classified (packed samples)', 'Misclassified (packed samples)', 'Correctly classified (unpacked samples)', 'Misclassified (unpacked samples)']
            xlabels = ['FP (packed)', 'FP (unpacked)', 'TN (packed)', 'TN (unpacked)', 'TP (packed)', 'FN (packed)', 'TN+TP (packed)', 'FP+FN (packed)', 'TP+TN (unpacked)', 'FP+FN (unpacked)']
            data = [fp_packed_scores, fp_unpacked_scores, tn_packed_scores, tn_unpacked_scores, tp_packed_scores, fn_packed_scores, t_packed_scores, f_packed_scores, t_unpacked_scores, f_unpacked_scores]
            colors = ['darkred', 'crimson', 'blue', 'green', 'yellow', 'gray', 'darkblue', 'darkgreen', 'red', 'black']
            fig = plt.figure(figsize=(10, 3), dpi=300)
            fig.set_size_inches(10, 2)
            ax = fig.add_subplot(111)
            ax.xaxis.tick_top()
            # ax.set_title('Prediction scores'.format(ratio, ratio2))
            FONTSIZE = 13
            bplot = ax.boxplot(data, patch_artist=False, sym='')
            ax.set_xticklabels(xlabels, rotation='vertical', fontsize=FONTSIZE)
            ax.set_ylim([0.5, 1])
            # for patch, color in zip(bplot['boxes'], colors):
            #     patch.set_facecolor(color)
            ax.set_xlabel('Test set', fontsize=FONTSIZE)
            ax.set_ylabel('Prediction score', fontsize=FONTSIZE-1)
            plotpath = "{}/scores-{}-{}.pdf".format(os.path.dirname(res_path), ratio, ratio2)
            plt.savefig(plotpath, bbox_inches='tight')
            plt.close()

            print("-------CONFIDENCE SCORES---------")
            for label, d in zip(xlabels, data):
                print('{}: {}'.format(label, get_mean(d)))
            print("--------------")

if __name__ == '__main__':
    scores_box_plot(sys.argv[1])
