import pandas as pd
import numpy as np
import sklearn
import sklearn.naive_bayes
import sklearn.ensemble
import sklearn.neighbors
import sklearn.pipeline
import sklearn.linear_model
from sklearn.externals import joblib
from sklearn.metrics import confusion_matrix
import sys
import pykka
import sqlite3
import importlib
import ujson as json
import exp_util

'''
Main module that contains functions to run an experiment of the paper.

Usage:
    python3 training.py config_exp0

Dependencies:
    * config_exp0.py: a python file that contains settings for the experiment
    * actor.py: threading module for running experiment concurrently

Notes:
    * if config.n_workers is set to 1 the experiments are runned in the main thread sequentially
    * debug is a global used to print additional informations
    * the seed is fixed and every thread uses it (summed with #round) for reproducibility
'''



NUMPY_SEED = 17
debug = True
drop_columns = exp_util.DROP_COLUMNS

def dprint(*obj):
    '''
    helper function
    :param obj: string or iterable to print if debug is set
    '''
    global debug
    if debug:
        print('-- DEBUG:', *obj)

def get_model(model_name, n_jobs):
    '''
    :param model_name: The name of the classifier
    :return: An sklearn instantiation of classifier
    '''

    if model_name == 'rf':
        return sklearn.ensemble.RandomForestClassifier(n_estimators=100, n_jobs=n_jobs, random_state=NUMPY_SEED)
    if model_name == 'perceptron':
        return sklearn.neural_network.MLPClassifier(n_jobs=n_jobs, random_state=NUMPY_SEED)
    elif model_name == 'dt': # decision tree
        return sklearn.tree.DecisionTreeClassifier(splitter='best', criterion='gini',
                                                  max_features=2200, random_state=NUMPY_SEED)
    elif model_name == 'lsvm':
        return sklearn.svm.LinearSVC(penalty='l1', loss='squared_hinge', dual=False, random_state=NUMPY_SEED, max_iter=1000) # max_iter =10000 for all experiments, except when the training set is huge, we set it to 1000. Experiment withheld-packer
    elif model_name == 'svc':
        return sklearn.svm.SVC(kernel='rbf', probability=True, random_state=NUMPY_SEED)
    elif model_name == 'et': # extra tree
        return sklearn.ensemble.ExtraTreesClassifier(n_estimators=50, n_jobs=n_jobs, random_state=NUMPY_SEED)
    elif model_name == 'bagc': # bagging classifier
        return sklearn.ensemble.BaggingClassifier(n_estimators=100, max_features=1600,
                                                  base_estimator=None, bootstrap=False,
                                                  max_samples=0.65, n_jobs=n_jobs, random_state=NUMPY_SEED)
    elif model_name == 'boost': # bagging classifier
        import xgboost
        return xgboost.sklearn.XGBClassifier(n_jobs=n_jobs, random_state=NUMPY_SEED)
    elif model_name == 'naive':
        return sklearn.naive_bayes.GaussianNB(random_state=NUMPY_SEED)
    elif model_name == 'knn':
        return sklearn.neighbors.KNeighborsClassifier(n_jobs=n_jobs, algorithm='ball_tree', p=1, n_neighbors=3, random_state=NUMPY_SEED)
    else:
        assert False


def normalize(model_name, original):
    '''
    Data normalization, useful for only svm classifier
    :param model_name: The name of the classifier
    :param original: The original pandas dataframe
    :return: It returns the normalized pandas dataframe if the model is svm, otherwise returns the original dataframe
    '''

    if model_name == 'lsvm' or model_name == 'svc':
        labels = original[['packed', 'benign', 'malicious', 'sample_sha1']]
        _df = original.drop(columns=drop_columns, axis=1, errors='ignore')
        normalized = sklearn.preprocessing.normalize(_df)
        df = pd.DataFrame(data=normalized, index=_df.index, columns = _df.columns)
        df[['packed', 'benign', 'malicious', 'sample_sha1']] = labels
        # print("Normalizing")
        return df
    else:
        return original

def remove_cols(df, ll):
    print("removing {} features".format(len(ll)))
    df.drop(columns=ll, axis=1, inplace=True)
    return df

def drop_some_features(df, used):
    '''
    Remove certain features from the pandas dataframe
    :param df: the src pandas dataframe
    :param features: name of the family of features to mantain
    :return: pandas dataframe
    '''
    possible_features = set(['header', 'strings', 'rich', 'sections', 'dll', 'import', 'generic', 'ngrams', 'opcodes'])

    to_remove = list(possible_features - set(used))

    cols = list(df.columns)
    if 'ngrams' in to_remove:
        df = remove_cols(df, [c for c in cols if c.startswith('ngram_')])
    if 'opcodes' in to_remove:
        df = remove_cols(df, [c for c in cols if c.startswith('opcode_')])
    if 'generic' in to_remove:
        df = remove_cols(df, [c for c in cols if c.startswith('generic_')])
    if 'strings' in to_remove:
        df = remove_cols(df, [c for c in cols if c.startswith('string_')])
    if 'rich' in to_remove:
        df = remove_cols(df, [c for c in cols if c.startswith('rich_')])
    # if 'export' in to_remove:
    #     df = remove_cols(df, [c for c in cols if c.startswith('exp_') or 'api_export_nb' == c])
    if 'import' in to_remove:
        df = remove_cols(df, [c for c in cols if c.startswith('imp_') or 'api_import_nb' == c])
    if 'dll' in to_remove:
        df = remove_cols(df, [c for c in cols if c.endswith('.dll') or 'dll_import_nb' == c])
    # if 'entropy' in to_remove:
    #     df = remove_cols(df, [c for c in cols if '_entropy' in c])
    if 'sections' in to_remove:
        pe = set([c for c in cols if c.startswith('pesection')])
        # entr = set([c for c in cols if '_entropy' in c])
        df = remove_cols(df, list(pe))
    if 'header' in to_remove:
        df = remove_cols(df, [c for c in cols if c.startswith('header_')])
    return df


def get_features_importances(model_name, model):
    '''
    This function extracts the features importance vector of weights of the given classifier
    :param model_name: The name of the classifier
    :param model: The sklearn instance of classifier
    :return: List of features weights
    :rtype: list
    '''

    if model_name == 'rf':
        importances = model.feature_importances_
        # std = np.std([tree.feature_importances_ for tree in model.estimators_], axis=0)
    elif model_name == 'lsvm':
        importances = model.coef_
        importances = importances[0]
    elif model_name == 'svc':
        return None
    elif model_name == 'dt':
        importances = model.feature_importances_
    elif model_name == 'et':
        importances = model.feature_importances_
    elif model_name == 'boost':
        importances = model.feature_importances_
    elif model_name == 'bagc':
        # Note: in case of decision trees as base estimators, the bottom line works well!
        importances = np.mean([tree.feature_importances_ for tree in model.estimators_], axis=0)
    elif model_name == 'knn':
        return None
    elif model_name == 'naive':
        return None
    else:
        assert False
    return list(importances)

def load_dataframe(df, model_name, features):
    '''
    Read a pandas dataframe, normalize it and remove features if needed
    '''
    # original = pd.read_pickle(input_path) # dataframe from prepare.py
    # normalize if svm
    if features != 'all' and features != ['all']:
        assert type(features) is list
        df = drop_some_features(df, features)
        verify_only_features_laded(df)
        print('Using features:', features, df.shape)
    return df

def verify_only_features_laded(df):
    for c in df.columns:
        if c in ['api_import_nb', 'dll_import_nb']:
            pass
        elif c.startswith('rich_') or c.startswith('generic_') or c.startswith('imp_') or c.startswith('header_') or c.startswith('ngram_') or c.startswith('opcode_') or c.startswith('pesection') or c.startswith('string_') or c.endswith('.dll'):
            pass
        else:
            if c not in drop_columns:
                print("column: {} should not be loaded".format(c))
                assert False

def main(conf_file=''):
    '''
    This function iterates between different ratio of malicious / benign, packed/unpacked
    It evaluates an sklearn model for the given model_name against the dataset
    :param conf_file: Location of the configuration file
    :rtype None
    '''
    global debug
    assert conf_file != ''
    if conf_file[-3:] == '.py':
        conf_file = conf_file[:-3]
    print('Using as configuration file:', conf_file)
    conf = importlib.import_module(conf_file)
    model_name = conf.model_name
    df = conf.dataframe
    features = conf.features
    database_location = conf.database
    global res_dir
    res_dir = '/'.join(database_location.split('/')[:-1])
    combs = conf.iterations
    n_workers = conf.n_workers
    n_jobs = conf.cores_per_worker

    compute_conf_score = True
    if hasattr(conf, 'compute_conf_score'):
        compute_conf_score = conf.compute_conf_score 

    print("Using", model_name, "as classifier with features:", features)
    df = load_dataframe(df, model_name, features)
    df = conf.process_dataset(df, NUMPY_SEED)

    # if 'unpacked_sample_id' in df.columns:
    #     packed_benign       = df[(df.benign == 1) & (df.packed == 1)][['unpacked_sample_id']]
    #     unpacked_benign     = df[(df.benign == 1) & (df.packed == 0)][['unpacked_sample_id']]
    #     packed_malicious    = df[(df.benign == 0) & (df.packed == 1)][['unpacked_sample_id']]
    #     unpacked_malicious  = df[(df.benign == 0) & (df.packed == 0)][['unpacked_sample_id']]
    # else:
    packed_benign       = df[(df.benign == 1) & (df.packed == 1)].index.to_frame()
    unpacked_benign     = df[(df.benign == 1) & (df.packed == 0)].index.to_frame()
    packed_malicious    = df[(df.benign == 0) & (df.packed == 1)].index.to_frame()
    unpacked_malicious  = df[(df.benign == 0) & (df.packed == 0)].index.to_frame()

    indices = (packed_benign, unpacked_benign, packed_malicious, unpacked_malicious)

    dprint("four sets indices are ready now!")

    # read and divide dataframe
    from actor import ConsumerActor
    # Create table
    conn = sqlite3.connect(database_location)
    cur = conn.cursor()
    try:
        cur.execute('''CREATE TABLE results
                  (ratio_mal real, ratio_ben real, round integer, features text, weights text, results text, confidence text)''')
        conn.commit()
    except:
        pass

    done = list(cur.execute('select ratio_ben, ratio_mal, round from results'))
    if done:
        print('Total iterations is:', len(combs))
        combs = list(set(combs) - set(done))
    print('Number of iterations remaining:', len(combs))

    if n_workers == 1:
        for query in run_mono(model_name, df, indices, combs, conf.divide_dataset, n_jobs, compute_conf_score):
            cur.execute(*query)
            conn.commit()
    else:
        tasks = [] # keep track of (workers, futures)
        for c in combs[:n_workers]:
            w = ConsumerActor.start(df, indices, c, model_name, conf.divide_dataset, n_jobs, res_dir, compute_conf_score)
            fut = w.ask({'start': 'ok'}, block=False) # make worker run experiment
            tasks.append((w, fut))
        combs = combs[n_workers:]

        idx = 0 # simple circular counter
        while len(combs) > 0 or len(tasks) > 0:
            idx += 1
            if idx >= n_workers or idx >= len(tasks):
                idx = 0
            w, f = tasks[idx]
            try:
                id, query = f.get(timeout=1)
                print('Burning:', id)
                w.stop()
                if isinstance(query, Exception):
                    # warning was raised and sklearn threw
                    # https://github.com/scikit-learn/scikit-learn/pull/9569
                    assert type(id) is tuple
                    print('ID:', id, 'threw. Work discarded:', query)
                    combs.append(id) # schedule again

                if len(combs) > 0:
                    # substitute with another worker
                    w = ConsumerActor.start(df, indices, combs.pop(), model_name, conf.divide_dataset, n_jobs, res_dir, compute_conf_score)
                    f = w.ask({'start': 'ok'}, block=False) # start experiment on worker thread, msg ignored
                    tasks[idx] = (w, f)
                else:
                    del(tasks[idx])

                if type(query) is tuple:
                    cur.execute(*query)
                    conn.commit()
                    print('ID:', id, 'wrote to sqlite3 store')
                    print('Remainings:', len(combs))
            except pykka.Timeout as t:
                pass

    print('DONE!')
    if not debug:
        pykka.ActorRegistry().stop_all()


def run_mono(model_name, df, indices, combs, divide_fun, n_jobs, compute_conf_score):
    '''
    Run the experiments in a linear fashion. No concurrency, useful for debugging.
    :param model_name: name of the model
    :param df: tuple of (packed ben, unpacked ben, packed mal, unpacked mal)
    :param indices: store indices for four sets of packed_benign, unpacked_benign, packed_malicious, unpacked_malicious
    :param combs: the combinations of (ratio_ben, ratio_mal, round) as defined by config file
    :rtype: yield string (sql query to be executed)
    '''
    cnt = len(combs)
    for c in combs:
        ratio_ben, ratio_mal, round = c
        dprint('starting experiment')
        res = experiment(model_name, df, indices, (ratio_ben, ratio_mal), round, divide_fun, n_jobs, res_dir, compute_conf_score)
        dprint('dumping res["results"]')
        results = json.dumps(res['results'])
        if round == 0:
            conf = json.dumps(res['confidence'])
            dprint('dumping res["confidence"]')
            features = json.dumps(res['importances'][0])
            dprint('dumping res["importances"][0]')
            weights = json.dumps(res['importances'][1])
            dprint('dumping res["importances"][1]')
            query = ('''INSERT INTO results VALUES (?, ?, ?, ?, ?, ?, ?)''',
                    (ratio_mal, ratio_ben, round, features, weights, results, conf))

        else:
            query = ('''INSERT INTO results VALUES (?, ?, ?, NULL, NULL, ?, NULL)''', (
                ratio_mal, ratio_ben, round, results))
        dprint('yielding query of size:', len(query))
        cnt -= 1
        dprint('{} remaining'.format(cnt))
        yield query


def experiment(model_name, df, indices, ratio, round, divide_fun, n_jobs, res_dir, compute_conf_score):
    '''
    Single round of the experiment for a determined ratio.
    The model is instantied, trained, tested against a dataset
    and results are stored
    :param model_name: The name of the model
    :param df: pandas dataframe containing the feature vector for all the samples
    :param indices: store indices for four sets of packed_benign, unpacked_benign, packed_malicious, unpacked_malicious
    :param ratio: Tuples of ratio of benign / malicious packed
    :param round: counter of rounds
    :param divide_fun: function to divide the dataset, defined in config
    :rtype Dictionary
    '''
    id = '{}-{}-{}'.format(ratio[0], ratio[1], round)
    dprint('Entered experiment:', id)
    ratio_ben, ratio_mal = ratio

    # split between test, train
    training_packed_benign, testing_packed_benign, training_unpacked_benign, testing_unpacked_benign, training_packed_malicious, testing_packed_malicious, training_unpacked_malicious, testing_unpacked_malicious = divide_fun(indices, ratio_ben, ratio_mal, NUMPY_SEED + round)
    # training_packed_benign, testing_packed_benign, training_unpacked_benign, testing_unpacked_benign, training_packed_malicious, testing_packed_malicious, training_unpacked_malicious, testing_unpacked_malicious = divide_fun(df, ratio_ben, ratio_mal, NUMPY_SEED+round)

    # dprint('dividing dataset')
    train_indices = training_packed_malicious + training_packed_benign + training_unpacked_malicious + training_unpacked_benign
    test_indices = testing_packed_malicious + testing_packed_benign + testing_unpacked_malicious + testing_unpacked_benign

    verify_test_train_separated(train_indices, test_indices)

    # it means, to scale up, we need to work only on good features.
    # We get them from the RF classifier
    good_features = None
    if model_name == 'svc' or model_name == 'lsvm':
        with open('{}/features-{}-{}.json'.format(res_dir.replace(model_name, "rf"), ratio_ben, ratio_mal), 'r') as f:
            rf_res = json.load(f)
            rf_features = rf_res['features']
            rf_weights = rf_res['weights']
            num = 10000
            good_features = [f for _, f in sorted(zip(rf_weights, rf_features), reverse=True)[:num]]
            print("Only top {} features from RF considered for trainning SVM".format(num))
            # rf_weights = [w for w, _ in sorted(zip(rf_weights, rf_features), reverse=True)[:num]]
        df = df[good_features + [c for c in drop_columns if c in df.columns]]
        # df = normalize(model_name, df)
    x_train = df[df.index.isin(train_indices)]
    dprint('done with dividing')
    # labels are being malicious or benign
    y_train = np.asarray(x_train['malicious'].values)
    # remove labels related to packing and type of binary
    x_train = x_train.drop(columns=drop_columns, axis=1, errors='ignore')

    # train model on training set
    model = get_model(model_name, n_jobs)
    dprint('Doing training', id)
    dprint("training size: {}".format(len(x_train)))
    model.fit(x_train, y_train)

    # importance_result = None
    if round == 0:
        weights = get_features_importances(model_name, model)
        if weights is not None:
            importances = (json.dumps(list(x_train.columns)), json.dumps(weights))
            dprint('Got importances', id)

            with open('{}/features-{}-{}.json'.format(res_dir, ratio_ben, ratio_mal), 'w') as f:
                json.dump({"weights": weights, "features": list(x_train.columns)}, f)
        else:
            importances = (json.dumps([]), json.dumps([]))
        joblib.dump(model, '{}/model-{}-{}.joblib'.format(res_dir, ratio_ben, ratio_mal))
    else:
        importances = None

    # temporarily store the size of the sets used
    stats = {'ratio_ben': ratio_ben * 100, 'ratio_mal': ratio_mal * 100,
            'training_packed_malicious': len(training_packed_malicious),
            'training_unpacked_benign': len(training_unpacked_benign),
            'training_packed_benign': len(training_packed_benign),
            'training_unpacked_malicious': len(training_unpacked_malicious),
            'testing_unpacked_malicious': len(testing_unpacked_malicious),
            'testing_packed_benign': len(testing_packed_benign),
            'testing_unpacked_benign': len(testing_unpacked_benign),
            'testing_packed_malicious': len(testing_packed_malicious)}
    dprint(stats)

    # evaluating on a dataset with same ratio as training dataset
    # print("evaluating on the test dataset with the same ratio as the training dataset")
    packed_test = df[df.index.isin(testing_packed_benign + testing_packed_malicious)]
    unpacked_test = df[df.index.isin(testing_unpacked_benign + testing_unpacked_malicious)]
    test = (packed_test, unpacked_test)

    if round == 0 and compute_conf_score:
        results, conf = evaluate(model_name, model, test, stats, do_conf_score=True)
    else:
        results, conf = evaluate(model_name, model, test, stats, do_conf_score=False)

    dprint('Done evaluating, returning:', id)
    return {'results': results, 'confidence': conf, 'importances': importances, 'model': model}


def evaluate(model_name, model, test, results, do_conf_score=False):
    '''
    Evaluate the current trained model on a test dataset (via model_score function)
    Store results with appropriate resultClass
    :param model_name: The name of the model
    :param model: sklearn classifier object
    :param test: pandas dataframe containing the dataset to test against
    :param resultObj: resultClass object for storing results
    :rtype: None
    '''
    packed_test, unpacked_test = test

    tn_packed, fp_packed, fn_packed, tp_packed, packed_conf_dist = \
        model_score(model, packed_test)
    tn_unpacked, fp_unpacked, fn_unpacked, tp_unpacked, unpacked_conf_dist \
        = model_score(model, unpacked_test)

    fp = fp_packed + fp_unpacked
    tp = tp_packed + tp_unpacked
    tn = tn_packed + tn_unpacked
    fn = fn_packed + fn_unpacked

    results.update({'fn_packed': int(fn_packed), 'fn_unpacked': int(fn_unpacked),
            'tn_packed': int(tn_packed), 'tn_unpacked': int(tn_unpacked),
            'fp_packed': int(fp_packed), 'fp_unpacked': int(fp_unpacked),
            'tp_packed': int(tp_packed), 'tp_unpacked': int(tp_unpacked),
            'fn': int(fn), 'tn': int(tn), 'fp': int(fp), 'tp': int(tp)})
    if do_conf_score:
        conf_dist = conf_dist_to_dict(packed_test, packed_conf_dist)
        conf_dist.update(conf_dist_to_dict(unpacked_test, unpacked_conf_dist))
        return (results, conf_dist)
    else:
        return (results, None)


def conf_dist_to_dict(x_list, c_list):
    '''
    Helper function that "formats" the confidence score
    to a format used in analysis by us
    @Hojjat, expand if needed
    '''
    assert len(x_list) == len(c_list)
    if not len(x_list):
        return {}
    conf_dist = {}
    c = 0
    for index, x in x_list.iterrows():
        conf_dist[index] = {'sha1': x['sample_sha1'], 'label': x['malicious'], 'packed': x['packed'], 'conf': float(max(c_list[c][0], c_list[c][1])), 'predict': int(np.argmax(c_list[c]))}
        c += 1
    return conf_dist


def model_score(model, x):
    '''
    Evaluate metric for model's prediction against x
    :param model: sklearn classifier obj
    :param x: pandas dataframe containing samples
    :return: tn_packed, fp_packed, fn_packed, tp_packed, packed_conf_dist
    :rtype: List
    '''
    if len(x) == 0:
        return (0, 0, 0, 0, [])
    y = np.asarray(x['malicious'].values)
    x = x.drop(columns=drop_columns, axis=1, errors='ignore')

    conf_dist = []
    if(type(model) == sklearn.svm.LinearSVC):
        class_prob = model.predict(x)
        for c in class_prob:
            tmp = [0, 0]
            tmp[int(c)] = 1
            conf_dist.append(tmp)
    else:
        class_prob = model.predict_proba(x)
        for c in class_prob:
            conf_dist.append(list(c))
    predictions = model.predict(x)

    # just make sure, confusion matrix see both labels!
    y = np.append(y, [0, 0, 1, 1])
    predictions = np.append(predictions, [0, 1, 0, 1])
    l = list(confusion_matrix(y, predictions).ravel()) # (tn, fp, fn, tp)
    # subtract the one which we added above
    l = [i-1 for i in l]
    l.append(conf_dist)
    return l

def verify_test_train_separated(train_indices, test_indices):
    train_indices = set(train_indices)
    test_indices = set(test_indices)

    assert len(train_indices) + len(test_indices) == len(train_indices.union(test_indices))


if __name__ == '__main__':
    models = ['rf', 'dt', 'naive', 'knn', 'bagc', 'lsvm', 'svc', 'et', 'boost', 'mlp']
    main(conf_file=sys.argv[1])
