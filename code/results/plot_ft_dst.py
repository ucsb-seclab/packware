import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
# import matplotlib.ticker as mtick
import sys
sys.path.append('../')
import util
PACKER_NAMES = {'upx': 'UPX', 'themida-v2': 'Themida', 'obsidium': 'Obsidium', 'telock': 'tElock', 'mpress': 'MPRESS', 'petite': 'Petite', 'dolphin-dropper-3': 'dolphin-dropper-3', 'pelock': 'PELock', 'pecompact': 'PECompact', 'kkrunchy': 'kkrunchy'}

def plot_feature_dist(dist_b, dist_m, packer, feature, x_log=False, y_log=False, bins=20, cdf=0, normed=True, x_max=None):
    plt.figure(figsize=(9, 4), dpi=300)
    ax = plt.subplot(111)
    FONTSIZE = 20
    ax.tick_params(axis='both', labelsize=FONTSIZE-2)

    if packer == 'lab':
        ax.set_xlabel('Feature {}'.format(feature), fontsize=FONTSIZE)
        if normed:
            ax.set_ylabel('Ratio of samples', fontsize=FONTSIZE)
        else:
            ax.set_ylabel('Number of samples', fontsize=FONTSIZE)

    if packer == 'lab':
        blabel = 'Benign (lab)'
        mlabel = 'Malicious (lab)'
    else:
        blabel = 'Benign (packed w. {})'.format(PACKER_NAMES[packer])
        mlabel = 'Malicious (packed w. {})'.format(PACKER_NAMES[packer])
    ax.hist(dist_b, label=blabel, color='black', linestyle='--', histtype='step', bins=bins, cumulative=cdf, normed=normed)
    ax.hist(dist_m, label=mlabel, color='crimson', histtype='step', bins=bins, cumulative=cdf, normed=normed)
    if x_max:
        plt.xlim([0, x_max])
    # ax.set_xlim([0, 1e7])
    if x_log:
        plt.xscale('log')
    if y_log:
        plt.yscale('log')
    # ax.grid(color='black', linestyle='dotted', linewidth=0.2)
    if packer == 'lab':
        ax.legend(fancybox=True, framealpha=0.5, fontsize=FONTSIZE)

    plt.savefig('../../plots/feature-dist-{}-{}.pdf'.format(feature, packer), bbox_inches='tight')
    plt.close()

def plot_feature_dist_packers(df, feature, cdf, x_max):
    packers = list(df.packer_name.unique())
    for packer in packers:
        if packer != 'none':
            dfp = df[df.packer_name == packer]
            dfb = dfp[dfp.benign]
            dfm = dfp[dfp.malicious]
            plot_feature_dist(dfb[feature], dfm[feature], packer, feature, cdf=cdf, x_max=x_max)
    df = df[df.packer_name != 'none']
    dfb = df[df.benign]
    dfm = df[df.malicious]
    plot_feature_dist(dfb[feature], dfm[feature], 'lab', feature, cdf=cdf, x_max=x_max)

def plot_apiImportNum():
    f = 'api_import_nb'
    cols = util.LABELS + [f]
    df = util.load_wildlab_df()
    cols = [c for c in cols if c in df.columns]
    df = df[cols]
    plot_feature_dist_packers(df, f, cdf=-1, x_max=80)

def plot_headerSizeOfInitializedData():
    pass

if __name__ == '__main__':
    plot_apiImportNum()

