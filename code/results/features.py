import matplotlib
matplotlib.use('Agg')

import matplotlib.pyplot as plt
import matplotlib.ticker as mtick
import numpy as np
import pandas as pd
import json
import sys
sys.path.append('../')
import ast
import os

CTGS = ['imp', 'dll', 'rich', 'sections', 'header', 'strings', 'ngrams', 'opcodes', 'generic', 'all']
CTGS_COLORS = {'imp': 'blue', 'dll': 'crimson', 'sections': 'gray', 'rich': 'purple', 'strings': 'yellow', 'all': 'black'}
CTGS_LINESTYLES = {'imp': '--', 'dll': ':', 'sections': '-.', 'rich': '-', 'all': '-'}
CTGS_LABELS = {'imp': 'Api Import', 'dll': 'Dll Import', 'sections': 'PE', 'rich': 'Rich Header', 'all': 'All'}
thrs = sorted([0.01, 0.001, 0.005, 0.0001, 0.0005, 0.0])

def features_plot3d(data, plot_name, label):

    X, Y, Z = data
    # X, Y = np.meshgrid(X, Y)
    Z = np.asarray(Z)

    max_num = Z[0][0]
    min_num = Z[0][0]

    for i in Z:
        for j in i:
            max_num = max(j, max_num)
            min_num = min(j, min_num)

    fig = plt.figure()
    ax = plt.subplot(111)

    ax.set_xlabel('Ratio of Packed Malicious in the Training Set')
    ax.set_ylabel('Ratio of Packed Benign in the Training Set')

    tick = mtick.FormatStrFormatter('%d%%')
    ax.xaxis.set_major_formatter(tick)
    ax.yaxis.set_major_formatter(tick)

    print("vmin: {}, vmax: {}".format(min_num, max_num))
    p = ax.pcolormesh(Z, cmap=plt.get_cmap('binary'), vmin=min_num, vmax=max_num)
    fig.colorbar(p).set_label(label)

    locs = list(range(0, len(X), 4))
    labels = ['{}%'.format(round(v * 5)) for v in locs]
    locs = [v + 0.5 for v in locs]
    plt.xticks(locs, labels)
    plt.yticks(locs, labels)

    plt.savefig(plot_name)
    plt.close()


def select_features_based_ctg(weights, features):
    assert len(weights) == len(features)
    ctg_features = {}
    for ctg in CTGS:
        ctg_features[ctg] = {'features': [], 'weights': []}
    for f, w in zip(features, weights):
        assert f != '0' and f != 'sample_score'
        if f.startswith('generic_'):
            ctg = 'generic'
        elif f.startswith('string_'):
            ctg = 'strings'
        elif f.startswith('header_'):
            ctg = 'header'
        elif 'imp_' in f or f == 'api_import_nb':
            ctg = 'imp'
        # elif 'exp_' in f or f == 'api_export_nb':
        #     ctg = 'exp'
        elif 'rich_' in f:
            ctg = 'rich'
        elif f.startswith('pesection'):
            ctg = 'sections'
        elif f.endswith('.dll') or f == 'dll_import_nb':
            ctg = 'dll'
        elif f.startswith('ngram_'):
            ctg = 'ngrams'
        elif f.startswith('opcode_'):
            ctg = 'opcodes'
        else:
            assert False
        ctg_features[ctg]['features'].append(f)
        ctg_features[ctg]['weights'].append(w)

        ctg = 'all'
        ctg_features[ctg]['features'].append(f)
        ctg_features[ctg]['weights'].append(w)
    return ctg_features


def select_features_based_thr(weights, features, thr):
    assert len(weights) == len(features)

    sel_weights = []
    sel_features = []
    for f, w in zip(features, weights):
        assert f != '0' and f != 'sample_score'
        if w > thr:
            sel_weights.append(w)
            sel_features.append(f)
    return sel_weights, sel_features

def get_features_dict(res, thrs, plots_path):
    print("building dicts for features")
    if os.path.exists('{}/used-features.json'.format(plots_path)):
        tmp = read_json('{}/used-features.json'.format(plots_path))
        weights_dict = tmp['weights']
        features_dict = tmp['features']
        return weights_dict, features_dict
    weights_dict = {k: {kk: {} for kk in sorted(res[list(res.keys())[0]].keys())} for k in sorted(res.keys())}
    features_dict = {k: {kk: {} for kk in sorted(res[list(res.keys())[0]].keys())} for k in sorted(res.keys())}
    for thr in thrs:
        for ratio in sorted(res.keys()):
            for ratio2 in sorted(res[ratio].keys()):
                if thr == 0:
                    weights = json.loads(res[ratio][ratio2]['weights'])
                    weights = ast.literal_eval(weights)
                    features = json.loads(res[ratio][ratio2]['features'])
                    features = ast.literal_eval(features)
                else:
                    weights = weights_dict[ratio][ratio2]['0.0']
                    features = features_dict[ratio][ratio2]['0.0']
                weights, features = select_features_based_thr(weights, features, thr)
                thr = str(thr)
                weights_dict[ratio][ratio2][thr] = weights
                features_dict[ratio][ratio2][thr] = features
    write_json('{}/used-features.json'.format(plots_path), {'weights': weights_dict, 'features': features_dict})
    return weights_dict, features_dict

def features_heatmap(res, plots_path):
    make_dir('{}/heatmap'.format(plots_path))
    weights_dict, features_dict = get_features_dict(res, thrs, plots_path)
    print("features dicts are built")
    for thr in thrs:
        for ctg in CTGS:
            heatmap_array = []
            heatmap_array_avg = []
            for ratio in sorted(res.keys()):
                tmp = []
                tmp_avg = []
                for ratio2 in sorted(res[ratio].keys()):

                    weights = weights_dict[ratio][ratio2][thr]
                    features = features_dict[ratio][ratio2][thr]
                    weights = select_features_based_ctg(weights, features)[ctg]['weights']

                    tmp.append(len(weights))
                    if len(weights):
                        tmp_avg.append(sum(weights) / len(weights))
                    else:
                        tmp_avg.append(0)
                heatmap_array.append(tmp)
                heatmap_array_avg.append(tmp_avg)

            X = sorted([round(float(x) * 100) for x in res.keys()])
            Y = sorted([round(float(x) * 100) for x in res.keys()])
            features_plot3d((X, Y, heatmap_array), '{}/heatmap/features-{}-heatmap-thr{}.pdf'.format(plots_path, ctg, thr), '# Features')
            features_plot3d((X, Y, heatmap_array_avg), '{}/heatmap/avg-weights-{}-heatmap-thr{}.pdf'.format(plots_path, ctg, thr), 'Average Weights of Features')

            print("ctg: {}, thr: {}".format(ctg, thr))


def features_ctg_piechart(res, plots_path):
    make_dir('{}/piechart'.format(plots_path))

    weights_dict, features_dict = get_features_dict(res, thrs, plots_path)

    ctgs = CTGS[1:]
    all_colors = ['blue', 'yellow', 'red', 'green', 'purple', 'brown']
    print("features dicts are built")
    for thr in thrs:
        make_dir('{}/piechart/{}'.format(plots_path, thr))
        for ratio in sorted(res.keys()):
            for ratio2 in sorted(res[ratio].keys()):
                labels = []
                sizes = []
                colors = []
                weights = weights_dict[ratio][ratio2][thr]
                features = features_dict[ratio][ratio2][thr]
                ctg_features = select_features_based_ctg(weights, features)
                for ctg, color in zip(ctgs, all_colors):
                    ctg_weights = ctg_features[ctg]['weights']
                    if len(ctg_weights):
                        sizes.append(len(ctg_weights))
                        labels.append(ctg)
                        colors.append(color)

                fig, ax = plt.subplots()
                ax.pie(sizes, labels=labels, autopct='%1.1f%%', shadow=True, startangle=90, colors=colors)
                ax.axis('equal')
                plt.savefig('{}/piechart/{}/features-piechart-{}-{}.pdf'.format(plots_path, thr, ratio, ratio2))
                plt.close()


def features_hist(res, plots_path):
    make_dir('{}/hist'.format(plots_path))
    for ratio in sorted(res.keys()):
        for ratio2 in sorted(res[ratio].keys()):

            features = res[ratio][ratio2]['weights'].replace('\"', '')
            features = ast.literal_eval(features)
            fig, ax = plt.subplots()
            ax.set_title('Features weights histogram (packed_benign_ratio={}, packed_malicious_ratio={})'.format(ratio, ratio2), fontdict={'fontsize': 10})
            n, bins, patches = plt.hist(features, normed=1, facecolor='green', cumulative=-1, histtype='step')
            # ax.set_xticklabels(xlabels, rotation=20, fontsize=8)
            # ax.set_ylim([0.5, 1])
            # for patch, color in zip(bplot['boxes'], colors):
            #     patch.set_facecolor(color)
            ax.set_yscale('log')
            ax.set_xscale('log')
            # ax.set_xlim([min_weight, max_weight])
            plotpath = "{}/hist/features-{}-{}.png".format(plots_path, ratio, ratio2)
            plt.savefig(plotpath)
            plt.close()


def features_ctg_barplot_sel_ratios(res, plots_path):

    weights_dict, features_dict = get_features_dict(res, thrs, plots_path)
    sel_ratios = [['1.0', '1.0']]
    # sel_ratios = [['0.0', '0.0'], ['0.0', '1.0'], ['1.0', '0.0'], ['0.5', '0.5'], ['0.5', '0.75'], ['0.75', '0.75'], ['1.0', '1.0']]
    x_labels = [r'$\rm r_{p,b}\!=\!r_{p,m}\!=\!0$', r'$\rm r_{p,b}\!=\!0,r_{p,m}\!=\!1$', r'$\rm r_{p,b}\!=\!1,r_{p,m}\!=\!0$', r'$\rmr_{p,b}\!=\!r_{p,m}\!=\!0.5$', r'$\rmr_{p,b}\!=\!0.5,r_{p,m}\!=\!0.75$', r'$\rm r_{p,b}\!=\!r_{p,m}\!=\!0.75$', r'$\rm r_{p,b}\!=\!r_{p,m}\!=\!1$']
    print("features dicts are built")

    data = {}
    ctgs = sorted(CTGS)
    for ctg in ctgs:
        sizes = []
        for ratio, ratio2 in sel_ratios:
            weights = weights_dict[ratio][ratio2]['0.0']
            features = features_dict[ratio][ratio2]['0.0']
            ctg_features = select_features_based_ctg(weights, features)
            ctg_weights = ctg_features[ctg]['weights']
            sizes.append(len(ctg_weights))
        data[ctg] = pd.Series(sizes, index=x_labels)

    for ratio, ratio2 in sel_ratios:
        print(ratio, ratio2)
        weights = weights_dict[ratio][ratio2]['0.0']
        features = features_dict[ratio][ratio2]['0.0']
        features = [f for _, f in sorted(zip(weights, features), reverse=True)][:10]
        print(sorted(weights, reverse=True)[:10])
        weights = [0] * len(features)
        ctg_features = select_features_based_ctg(weights, features)
        print(features)
        for ctg in ctgs:
            print(ctg, len(ctg_features[ctg]['weights']), ','.join(ctg_features[ctg]['features']))
    return
    data = pd.DataFrame(data)
    plt.figure(figsize=(8, 4), dpi=300)
    ax = plt.subplot(111)
    for ctg in CTGS:
        data[ctg].plot(ax=ax, color=CTGS_COLORS[ctg], label=CTGS_LABELS[ctg], logy=True, rot=10, linestyle=CTGS_LINESTYLES[ctg])

    # ax = data.plot(kind='line', color=colors, title='Feature Categories', logy=True, rot=45)
    # ax.set_xlabel('Different Classifiers Trained on Different Ratio of Packed Executables')
    ax.legend(loc="best", fancybox=True, framealpha=0.5, fontsize=9)
    ax.grid(color='black', linestyle='dotted', linewidth=0.5)
    ax.set_ylabel('# Features')
    locs, labels = plt.xticks()
    locs = locs[1:-1]
    plt.ylim(50, 3000)
    plt.xticks(locs, x_labels, fontsize=9)
    plt.title('# Features per Category for Different Classifiers')
    plt.savefig('{}/features-barplot-sel-ratios.pdf'.format(plots_path))
    plt.close()


def features_ctg_barplot(res, plots_path):
    make_dir('{}/barplot'.format(plots_path))

    weights_dict, features_dict = get_features_dict(res, thrs, plots_path)
    ctgs = sorted(CTGS)
    print("features dicts are built")
    for ratio in sorted(res.keys()):
        for ratio2 in sorted(res[ratio].keys()):
            data = {}
            for thr in thrs:
                sizes = []
                thr = str(thr)
                if thr not in weights_dict[ratio][ratio2]:
                    thr = '0'
                weights = weights_dict[ratio][ratio2][thr]
                features = features_dict[ratio][ratio2][thr]
                ctg_features = select_features_based_ctg(weights, features)
                for ctg in ctgs:
                    ctg_weights = ctg_features[ctg]['weights']
                    sizes.append(len(ctg_weights))

                data[thr] = pd.Series(sizes, index=ctgs)
            data = pd.DataFrame(data)
            # fig = plt.figure()
            colors = [CTGS_COLORS[ctg] for ctg in ctgs]
            ax = data.plot(kind='bar', color=colors, title='Feature Categories', logy=True, rot=45)
            # ax.set_xlabel('The threshold for selecting features with weights of greater than it')
            ax.set_ylabel('# Features')
            # locs, labels = plt.xticks()
            # import IPython
            # IPython.embed()
            # locs = locs[1:-1]
            # labels = list(data.index)
            # plt.xticks(locs, labels, fontsize=8)
            plt.savefig('{}/barplot/features-barplot-{}-{}.png'.format(plots_path, ratio, ratio2))
            plt.close()


def features_plot(res_path, plots_path, hist=False):
    res = read_json(res_path)

    if len(res.keys()) == 21:
        features_heatmap(res, plots_path)

    # features_ctg_barplot(res, plots_path)

    features_ctg_barplot_sel_ratios(res, plots_path)

    # features_ctg_piechart(res, plots_path)

    if hist:
        features_hist(res, plots_path)

def print_top_features(res_path, num):
    res = read_json(res_path)

    for ratio in sorted(res.keys()):
        for ratio2 in sorted(res[ratio].keys()):
            weights = json.loads(res[ratio][ratio2]['weights'])
            weights = ast.literal_eval(weights)
            features = json.loads(res[ratio][ratio2]['features'])
            features = ast.literal_eval(features)
            THR = sum(weights) / (len(weights) * 1.0) # mean
            THR = 0
            print('ratio: {}, ratio2: {}'.format(ratio, ratio2))
            import math
            s = 0
            for w in weights:
                s += w * w
            a = math.sqrt(s)
            print(sum(weights)/a)
            nonzero = [[w, f] for w,f in zip(weights, features) if w > THR]
            nonzerofeatures = [f for _, f in nonzero]
            nonzeroweights = [w for w,_ in nonzero]
            ctgs_nonzerofeatures = select_features_based_ctg(nonzeroweights, nonzerofeatures)
            ctgs_nonzerofeatures = {c: len(v['features']) for c, v in ctgs_nonzerofeatures.items()}
            print('\n'.join(['{} :{}'.format(round(w, 6), f) for w,f in sorted(zip(weights, features), reverse=True)[:num]]))
            features = [f for _,f in sorted(zip(weights, features), reverse=True)[:num]]
            weights = [w for w,_ in sorted(zip(weights, features), reverse=True)[:num]]
            ctgs_features = select_features_based_ctg(weights, features)
            ctgs_features = {c: len(v['features']) for c, v in ctgs_features.items()}
            # print(THR)
            # print(ctgs_features)
            print(' & '.join(['{} ({})'.format(ctgs_nonzerofeatures[ctg], ctgs_features[ctg]) for ctg in CTGS]))

def plot_feature_hist(dfb, dfm, f, res_path):
    for label, df in zip(['benign', 'malicious'], [dfb, dfm]):
        plotpath = '{}/feature-hist-{}-{}.png'.format(res_path, f, label)
        fig, ax = plt.subplots()
        ax.set_title('{} histogram for {} samples'.format(f, label), fontdict={'fontsize': 10})
        if 'name' in f:
            df[f].value_counts().plot(kind='bar')
        else:
            n, bins, patches = plt.hist(df[f], facecolor='green')
        # ax.set_xticklabels(xlabels, rotation=20, fontsize=8)
        # ax.set_ylim([0.5, 1])
        # for patch, color in zip(bplot['boxes'], colors):
        #     patch.set_facecolor(color)
        ax.set_yscale('log')
        # ax.set_xscale('log')
        # ax.set_xlim([min_weight, max_weight])
        plt.savefig(plotpath)
        plt.close()


def print_diff_stats(df, dfb, dfm, f, res_path):
    print("Feature: {}".format(f))
    if f == 'api_import_nb' or f == 'dll_import_nb' or f == 'api_export_nb' or 'name' in f or 'imp_' in f or f.endswith('.dll') or 'exp_' in f:
        b = dfb[['sample_sha1', f]].groupby(f).count().to_dict()['sample_sha1']
        b = {k: v for k, v in b.items() if v > 100}
        m = dfm[['sample_sha1', f]].groupby(f).count().to_dict()['sample_sha1']
        m = {k: v for k, v in m.items() if v > 100}
        print("only those with freq more than 100 samples")
        print('Benign dist.: {}'.format(b))
        print('Malicious dist.: {}'.format(m))
        plot_feature_hist(dfb, dfm, f, res_path)
    else:
        print("Benign ----> Mean: {}, Variance: {}".format(dfb[f].mean(), dfb[f].var()))
        print("Malicious ----> Mean: {}, Variance: {}".format(dfm[f].mean(), dfm[f].var()))
        plot_feature_hist(dfb, dfm, f, res_path)
    print("-------")

def write_json(filepath, data):
    with open(filepath, 'w') as f:
        json.dump(data, f)


def read_json(filepath):
    with open(filepath) as f:
        return json.load(f)

def make_dir(dir_path):
    if not os.path.exists(dir_path):
        os.makedirs(dir_path)

if __name__ == '__main__':
    # features_plot(sys.argv[1], sys.argv[2])
    print_top_features(sys.argv[1], int(sys.argv[2]))
