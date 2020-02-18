import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import ast
import json
from collections import Counter

FEATURE_NAMES = dict(
        pesection_2_entropy= '2nd section entropy',
        pesectionProcessed_resourcesMeanSize= 'Resources MEAN size',
        pesectionProcessed_entrypointSection_entropy= 'Entrypoint section entropy',
        pesectionProcessed_resources_nb= 'Resources num.',
        pesectionProcessed_sectionsMaxEntropy= 'Sections MAX entropy',
        pesectionProcessed_resourcesMaxSize= 'Resources MAX size',
        pesectionProcessed_resourcesMeanEntropy= 'Resources MEAN entropy',
        pesectionProcessed_resourcesMaxEntropy= 'Resources MAX entropy',
        pesectionProcessed_sectionsMeanEntropy= 'Sections MEAN entropy',
        pesectionProcessed_sectionsMeanSize= 'Sections MEAN size',
        pesectionProcessed_sectionsMaxSize= 'Sections MAX size',
        pesection_1_physicalAddress= '1st section address',
        pesection_1_virtualSize= '1st section virt. size',
        pesectionProcessed_resourcesMinSize= 'Resources MIN size',
        pesectionProcessed_sectionsMinVirtualSize= 'Sections MIN virt. size',
        pesectionProcessed_sectionsMaxVirtualSize= 'Sections MAX virt. size',
        pesection_2_virtualAddress= '2nd section virt. address',
        pesection_1_entropy= '1st section entropy',
        pesection_3_entropy= '3rd section entropy',
        pesectionProcessed_sectionsMeanVirtualSize= 'Sections MEAN virt. size',
        pesectionProcessed_entrypointSection_size= 'Entrypoint section size',
        pesection_3_virtualSize='3rd virtual size'
        )
FEATURE_NAMES['pesection_3_rawAddress(pointerToRawData)'] = '3rd section address'

# FEATURE_NAMES = dict(
#         pesection_2_entropy= 'Entropy of 2nd section',
#         pesectionProcessed_resourcesMeanSize= 'Mean size of resources',
#         pesectionProcessed_entrypointSection_entropy= 'Entropy of the entrypoint section',
#         pesectionProcessed_resources_nb= 'Number of resources',
#         pesectionProcessed_sectionsMaxEntropy= 'Max entropy of sections',
#         pesectionProcessed_resourcesMaxSize= 'Max size of resources',
#         pesectionProcessed_resourcesMeanEntropy= 'Mean entropy of resources',
#         pesectionProcessed_resourcesMaxEntropy= 'Max entropy of resources',
#         pesectionProcessed_sectionsMeanEntropy= 'Mean entropy of sections',
#         pesectionProcessed_sectionsMeanSize= 'Mean size of sections',
#         pesectionProcessed_sectionsMaxSize= 'Max size of sections',
#         pesection_1_physicalAddress= 'Address of 1st section',
#         pesection_1_virtualSize= 'Virtual size of 1st section',
#         pesectionProcessed_resourcesMinSize= 'Min size of resources',
#         pesectionProcessed_sectionsMinVirtualSize= 'Min virtual size of sections',
#         pesection_2_virtualAddress= 'Virtual address of 2nd section',
#         pesection_1_entropy= 'Entropy of 1st section',
#         pesection_3_entropy= 'Entropy of 3rd section',
#         pesectionProcessed_sectionsMeanVirtualSize= 'Mean virtual size of sections',
#         pesectionProcessed_entrypointSection_size= 'Size of the entrypoint section'
#         )
PACKER_NAMES = {'themida-v2': 'Themida', 'petite': 'Petite', 'upx': 'UPX', 'telock': 'tElock', 'pelock': 'PELock', 'pecompact': 'PECompact', 'obsidium': 'Obsidium', 'kkrunchy': 'kkrunchy', 'mpress': 'MPRESS'}

def plot_heatmap(data, plotpath):
    z = data['weight'].values
    y = data['packer'].unique()
    x = data['feature'].unique()
    Z = z.reshape(len(y), len(x))
    max_z = data['weight'].max()
    max_z = 0.1
    min_z = data['weight'].min()

    fig = plt.figure(figsize=(17, 4), dpi=600)
    ax = plt.subplot(111)
    ax.xaxis.tick_top()
    FONTSIZE = 16

    p = ax.pcolormesh(Z, cmap='binary', vmin=min_z, vmax=max_z, edgecolors='white')
    cb = fig.colorbar(p)
    cb.set_label('Feature Weights', fontsize=FONTSIZE)
    cb.ax.tick_params(labelsize=FONTSIZE-1)

    locs = list(range(0, len(y)))
    locs = [v + 0.5 for v in locs]
    labels = [PACKER_NAMES[k] for k in y]
    plt.yticks(locs, labels, fontsize=FONTSIZE)

    locs = list(range(0, len(x)))
    locs = [v + 0.5 for v in locs]
    labels = [FEATURE_NAMES[k] for k in x]
    plt.xticks(locs, labels, rotation=90, fontsize=FONTSIZE)
    # plt.xticks(locs, labels, rotation=40)
    # fig.autofmt_xdate()
    # for tick in ax.get_xticklabels():
    #     tick.set_rotation(70)
    plt.savefig('{}/expSinglePacker_pesections_plot_heatmap.pdf'.format(plotpath), bbox_inches='tight')
    plt.close()

if __name__ == '__main__':
    df = pd.DataFrame(columns=['feature', 'packer', 'weight'])
    all_features = {}
    sum_weights = Counter()
    exppath = '../../results/paper/experiments/exp-singlePacker/rf/lab-v3'
    for p in PACKER_NAMES:
        respath = '{}/{}/sections/exp.db.json'.format(exppath, p)
        with open(respath) as f:
            res = json.load(f)
        assert len(res.keys()) == 1
        res = res['1.0']
        assert len(res.keys()) == 1
        res = res['1.0']
        weights = json.loads(res['weights'])
        weights = ast.literal_eval(weights)
        features = json.loads(res['features'])
        features = ast.literal_eval(features)

        all_features[p] = {f: w for f, w in zip(features, weights)}

        for f, w in zip(features, weights):
            if w > 0:
                sum_weights[f] += w

    mean_weights = [[f, w/len(PACKER_NAMES)] for f, w in sum_weights.items()]
    mean_weights = sorted(mean_weights, reverse=True, key=lambda x: x[1])
    mean_weights = mean_weights[:20]
    print('\n'.join(['{}: {}'.format(f, w) for f, w in mean_weights]))

    idx = 1
    for p in PACKER_NAMES:
        for f, _ in mean_weights:
            df.loc[idx] = [f, p, all_features[p][f]]
            idx += 1

    plot_heatmap(df, '{}'.format(exppath))
