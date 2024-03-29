import os
import math
import shutil
import pefile
import array
import itertools
import traceback
import pandas as pd
import multiprocessing
from collections import Counter

import sys
sys.path.append('../../')
import util
sys.path.append('../richheader')
import rich_standalone as rich


# borrowed from https://github.com/Te-k/malware-classification/blob/master/generatedata.py
def get_entropy(data):
    if len(data) == 0:
        return 0.0
    occurences = array.array('L', [0]*256)
    for x in data:
        occurences[x if isinstance(x, int) else ord(x)] += 1

    entropy = 0
    for x in occurences:
        if x:
            p_x = float(x) / len(data)
            entropy -= p_x*math.log(p_x, 2)

    return entropy


# borrowed from (then modified a bit) https://kennethghartman.com/calculate-file-entropy/
def file_entropy(path):
    with open(path, 'rb') as f:
        byteArr = f.read()
        fileSize = len(byteArr)

    # calculate the frequency of each byte value in the file
    freqs = Counter()
    for byte in byteArr:
        freqs[byte] += 1
    freqList = [float(freqs[byte]) / float(fileSize) for byte in range(256)]

    # Shannon entropy
    ent = 0.0
    for freq in freqList:
        if freq > 0:
            ent = ent + freq * math.log(freq, 2)
    ent = -ent

    return ent, fileSize


# borrowed (and then a bit modified) from https://github.com/Te-k/malware-classification/blob/master/generatedata.py
def parse_resources(pe):
    entropies = []
    sizes = []
    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        try:
            for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if hasattr(resource_type, 'directory'):
                    for resource_id in resource_type.directory.entries:
                        if hasattr(resource_id, 'directory'):
                            for resource_lang in resource_id.directory.entries:
                                data = pe.get_data(resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size)
                                size = resource_lang.data.struct.Size
                                entropy = get_entropy(data)

                                entropies.append(entropy)
                                sizes.append(size)
        except Exception as e:
            print(e)
            traceback.print_exc()

    assert len(entropies) == len(sizes)
    if len(sizes):
        mean_entropy = sum(entropies) / float(len(entropies))
        min_entropy = min(entropies)
        max_entropy = max(entropies)
        mean_size = sum(sizes) / float(len(sizes))
        min_size = min(sizes)
        max_size = max(sizes)
        resources_nb = len(entropies)
    else:
        mean_entropy    = 0
        min_entropy     = 0
        max_entropy     = 0
        mean_size       = 0
        min_size        = 0
        max_size        = 0
        resources_nb    = 0


    secs = {}

    secs['pesectionProcessed_resourcesMeanEntropy'] = mean_entropy
    secs['pesectionProcessed_resourcesMinEntropy']  = min_entropy
    secs['pesectionProcessed_resourcesMaxEntropy']  = max_entropy

    secs['pesectionProcessed_resourcesMeanSize'] = mean_size
    secs['pesectionProcessed_resourcesMinSize']  = min_size
    secs['pesectionProcessed_resourcesMaxSize']  = max_size

    secs['pesectionProcessed_resources_nb'] = resources_nb

    return secs

def parse_imports(pe):
    dlls = []
    imps = []

    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode().lower()
            if not dll.endswith('.dll'):
                print("warning: {}".format(dll))
                dll = "{}.dll".format(dll.split('.dll')[0])
            dlls.append(dll)
            for imp in entry.imports:
                imp = imp.name
                if imp:
                    imp = imp.decode().lower()
                    imp = 'imp_{}'.format(imp)
                    imps.append(imp)

    return dlls, imps

def parse_exports(pe):

    exps = []
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        if len(pe.DIRECTORY_ENTRY_EXPORT.symbols):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                exp = exp.name
                if exp:
                    exp = exp.decode().lower()
                    exp = 'exp_{}'.format(exp)
                    exps.append(exp)

    return exps

def parse_sections(pe):
    secs = {}
    num = 1
    entrypoint_addr = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    entrypoint_valid = False
    for section in pe.sections:
        features = {}
        try:
            features['name'] = section.Name.decode().rstrip('\0')
        except:
            features['name'] = str(section.Name)

        # DON"T PANIC! just tryting to extract each bit of charactersitics into a separate feature. 32 is the length of Characteristics field
        characteristics = section.Characteristics
        characteristics = bin(characteristics)[2:]
        characteristics = '0' * (32 - len(characteristics)) + characteristics
        for i in range(32):
            features['characteristics_bit{}'.format(i)] = (characteristics[31-i] == '1')


        features['size']                            = section.SizeOfRawData
        features['virtualSize']                     = section.Misc_VirtualSize
        features['virtualAddress']                  = section.VirtualAddress
        features['physicalAddress']                 = section.Misc_PhysicalAddress
        features['entropy']                         = section.get_entropy()
        features['rawAddress(pointerToRawData)']    = section.PointerToRawData
        features['pointerToRelocations']            = section.PointerToRelocations
        features['numberOfRelocations']             = section.NumberOfRelocations

        for fname, fvalue in features.items():
            secs['pesection_{}_{}'.format(num, fname)] = fvalue

        if entrypoint_addr >= features['virtualAddress'] and (entrypoint_addr - features['virtualAddress']) < features['virtualSize']: # this is the sections which entry point is in it!!!
            for fname, fvalue in features.items():
                secs['pesectionProcessed_entrypointSection_{}'.format(fname)] = fvalue
            entrypoint_valid = True

        num += 1

    if not entrypoint_valid:
        return

    entropies = [value for feature, value in secs.items() if feature.endswith('_entropy')]
    if len(entropies):
        mean_entropy = sum(entropies) / float(len(entropies))
        min_entropy = min(entropies)
        max_entropy = max(entropies)
    else:
        mean_entropy = 0
        min_entropy = 0
        max_entropy = 0

    sizes = [value for feature, value in secs.items() if feature.endswith('_size')]
    if len(sizes):
        mean_size = sum(sizes) / float(len(sizes))
        min_size = min(sizes)
        max_size = max(sizes)
    else:
        mean_size = 0
        min_size = 0
        max_size = 0

    virtual_sizes = [value for feature, value in secs.items() if feature.endswith('_virtualSize')]
    if len(virtual_sizes):
        mean_virtual_size = sum(virtual_sizes) / float(len(virtual_sizes))
        min_virtual_size = min(virtual_sizes)
        max_virtual_size = max(virtual_sizes)
    else:
        mean_virtual_size = 0
        min_virtual_size = 0
        max_virtual_size = 0

    secs['pesectionProcessed_sectionsMeanEntropy']      = mean_entropy
    secs['pesectionProcessed_sectionsMinEntropy']       = min_entropy
    secs['pesectionProcessed_sectionsMaxEntropy']       = max_entropy

    secs['pesectionProcessed_sectionsMeanSize']         = mean_size
    secs['pesectionProcessed_sectionsMinSize']          = min_size
    secs['pesectionProcessed_sectionsMaxSize']          = max_size

    secs['pesectionProcessed_sectionsMeanVirtualSize']  = mean_virtual_size
    secs['pesectionProcessed_sectionsMinVirtualSize']   = min_virtual_size
    secs['pesectionProcessed_sectionsMaxVirtualSize']   = max_virtual_size

    secs.update(parse_resources(pe))

    return secs, num - 1

def parse_pe_header(pe):
    headers = {}
    opt_header = pe.OPTIONAL_HEADER

    fields = ['SizeOfHeaders', 'AddressOfEntryPoint', 'ImageBase', 'SizeOfImage', 'SizeOfCode', 'SizeOfInitializedData', 'SizeOfUninitializedData', 'BaseOfCode', 'BaseOfData', 'SectionAlignment', 'FileAlignment']
    for f in fields:
        headers['header_{}'.format(f)] = getattr(opt_header, f)

    coff_header = pe.FILE_HEADER
    fields = ['NumberOfSections', 'SizeOfOptionalHeader']
    for f in fields:
        headers['header_{}'.format(f)] = getattr(coff_header, f)

    # DON"T PANIC! just tryting to extract each bit of charactersitics into a separate feature. 32 is the length of Characteristics field
    characteristics = coff_header.Characteristics
    characteristics = bin(characteristics)[2:]
    characteristics = '0' * (16 - len(characteristics)) + characteristics
    for i in range(16):
        headers['header_characteristics_bit{}'.format(i)] = (characteristics[15-i] == '1')

    return headers

def parse_pe(sample_file):
    try:
        # print("extracting features for sample: {}".format(sample_file))

        pe = pefile.PE(sample_file)
        if pe.FILE_HEADER.Machine == 332: # we only 32bit samples
            dlls, imps = parse_imports(pe)
            exps = parse_exports(pe)
            x = parse_sections(pe)
            if x:
                sections, _ = x
            else:
                return None

            # assert 'pesection_1_name' in sections and sections['pesection_1_name'] == '.MPRESS1'
            headers = parse_pe_header(pe)

            richs = rich.parse_richheader(sample_file)
            rich_names = rich.get_rich_names()
            richs = {name: v for name, v in zip(rich_names, richs)}

            entropy, size = file_entropy(sample_file)
            generics = {'generic_fileSize': size, 'generic_fileEntropy': entropy}
            return {'headers': headers, 'imps': imps, 'exps': exps, 'dlls': dlls, 'sections': sections, 'rich': richs, 'generics': generics}

    except Exception as e:
        print(e)
        traceback.print_exc()
        return None

def extract_features_of_wild_sample(sample):
    sample_id, sample_file = sample

    res = parse_pe(sample_file)
    if res:
        return [sample_id, res]
    else:
        return [-1, -1]

def extract_features_of_lab_sample(filename):

    unpacked_sha1 = filename.split("/")[-1].split(".")[0]
    sha1 = util.compute_sha1(filename)

    if unpacked_sha1 == sha1:
        print("file {} is same as the unpacked version!!!!".format(filename))
        return [-1, -1, -1, -1]

    res = parse_pe(filename)

    if res:
        return [filename.split("/")[-1], unpacked_sha1, sha1, res]
    else:
        return [-1, -1, -1, -1]

def init_cols(df, features):

    features = {f: v for f, v in features.items() if f not in df.columns}
    cols = features.keys()
    print("adding {} columns".format(len(cols)))
    data = [[v['defval'] for f, v in features.items()]] * len(df)
    df2 = pd.DataFrame(data=data, columns=cols)
    df2.index = df.index
    print("appending to the current dataframe")
    df = pd.concat([df, df2], axis=1)
    print("done with adding the columns")

    return df

def get_defval_dtype(col):
    if col in ['api_import_nb', 'api_export_nb', 'dll_import_nb']:
        return 0, int
    elif '.dll' in col or 'imp_' in col or 'exp_' in col:
        return False, bool
    elif 'header_' in col:
        if 'characteristics' in col:
            return False, bool
        else:
            return 0, int
    elif col.startswith('pesection'):
        if 'name' in col:
            return 'none', object
        elif 'characteristics' in col:
            return False, bool
        elif 'entropy' in col:
            return 0.0, float
        else:
            return 0, int
    elif col == 'generic_fileEntropy':
        return 0.0, float
    elif col == 'generic_fileSize':
        return 0, int
    else:
        print(col)
        return 'invalid', object

def build_row_values(v):
    unpacked_sample_sha1 = v['unpacked_sample_sha1']
    sample_sha1 = v['sample_sha1']
    v = v['features']
    x = benign_df[benign_df.sample_sha1 == unpacked_sample_sha1]
    unpacked_sample_id = x.index[0]
    benign = x.iloc[0]['benign']
    malicious = x.iloc[0]['malicious']

    labels = {'sample_sha1': sample_sha1, 'unpacked_sample_sha1': unpacked_sample_sha1, 'unpacked_sample_id': unpacked_sample_id, 'packed': True, 'benign': benign, 'malicious': malicious, 'packer_name': packername, 'source': source}

    return put_features_in_row(v, labels)


def build_row_values_ember(v):
    unpacked_sample_sha1 = -1
    unpacked_sample_id = -1
    sample_sha1 = v['sample_sha1']
    malicious = v['label']
    benign = not v['label']
    v = v['features']
    source = 'wild-ember'
    packername = 'none'

    # print("WARNING:")
    # print("packed value set to the False as default value, you need to update it")
    # print("-----------------")
    packed = False

    labels = {'sample_sha1': sample_sha1, 'unpacked_sample_sha1': unpacked_sample_sha1, 'unpacked_sample_id': unpacked_sample_id, 'packed': packed, 'benign': benign, 'malicious': malicious, 'packer_name': packername, 'source': source}

    return put_features_in_row(v, labels)

def put_features_in_row(v, labels):
    dlls = set(v['dlls'])
    imps = set(v['imps'])
    exps = set(v['exps'])
    sections = v['sections']
    headers = v['headers']
    richs = v['rich']
    generics = v['generics']

    nbs = {'api_import_nb': len(imps), 'api_export_nb': len(exps), 'dll_import_nb': len(dlls)}
    vals = []
    warning_cols = set()
    for col in all_columns:
        if col.startswith('rich_'):
            vals.append(richs[col])
        elif col.startswith('header_'):
            vals.append(headers[col])
        elif col.startswith('pesection'):
            if col in sections:
                vals.append(sections[col])
            elif 'name' in col:
                vals.append('none')
            elif 'characteristics' in col:
                vals.append(False)
            else:
                vals.append(0)
        elif col.startswith('imp_'):
            vals.append(col in imps)
        elif col.endswith('.dll'):
            vals.append(col in dlls)
        elif col.startswith('exp_'):
            vals.append(col in exps)
        elif col.startswith('generic_'):
            vals.append(generics[col])
        elif col in nbs:
            vals.append(nbs[col])
        elif col in labels:
            vals.append(labels[col])
        else:
            warning_cols.add(col)
            vals.append(-1)

    # print("FILL values inserted for the following columns: {}".format(', '.join(warning_cols)))

    return vals

def add_samples_of_packer_to_pickle_file(df, res, packer_name, src):

    cur_sample_id = min(df.index)
    if cur_sample_id >= 0:
        cur_sample_id = -1
    else:
        cur_sample_id -= 1

    print("now computing the rows for new samples")
    global benign_df, all_columns, packername, source
    packername = packer_name
    source = src
    all_columns = df.columns
    benign_df = df[['benign', 'sample_sha1', 'malicious']]

    def generator():
        global cnt
        cnt = len(res)
        for r in res.values():
            yield r
            cnt -= 1
    gen = generator()
    N = 10000
    while True:
        print("building the row values")
        with multiprocessing.Pool() as p:
            rows = p.map(build_row_values, itertools.islice(gen, N))
        if rows:
            print("building the temp. dataframe")
            df2 = pd.DataFrame(data=rows, columns=df.columns)
            df2.index.name = 'sample_id'
            df2.index = [i for i in range(cur_sample_id, cur_sample_id - len(rows), -1)]
            cur_sample_id = cur_sample_id - len(rows)

            print("appending it to the current dataframe")
            df = pd.concat([df, df2])
            print("freeing some memory")
            del df2
            del rows
            print("saving the dataframe")
            util.save_wildlab_df(df)

            print("{} samples still need to be added to the dataframe".format(cnt))
            print("------")
        else:
            break
    return df

def add_samples_of_ember_to_pickle_file(df, res):

    cur_indices = df[df.source == 'wild-ember'].index
    if len(cur_indices):
        cur_sample_id = max(cur_indices) + 1
    else:
        cur_sample_id = max(df.index) + 100000

    print("now computing the rows for new samples")
    global all_columns
    all_columns = df.columns
    with multiprocessing.Pool() as p:
        rows = p.map(build_row_values_ember, res.values())

    print("building the new dataframe")
    df2 = pd.DataFrame(data=rows, columns=df.columns)
    df2.index.name = 'sample_id'
    df2.index = [i for i in range(cur_sample_id, cur_sample_id + len(rows))]

    print("appending it to the current dataframe")
    df = pd.concat([df, df2])

    print("now copying files")
    copy_ember_samples(res)

    util.save_wild_df(df)
    return df

def build_wild_pickle_file(df, res):
    df = util.load_wild_df()
    if df is None:
        df = df[['sample_sha1', 'benign', 'malicious', 'packed', 'unpacked_sample_sha1', 'unpacked_sample_id', 'packer_name']]
    features = get_all_features(res)

    df = init_cols(df, features)

    util.save_wild_df(df)

    c = len(res)
    print("importing {} samples features into the pickle file".format(c))
    for sample_id, v in res.items():
        c -= 1
        sample_id = int(sample_id)
        dlls = []
        for dll in v['dlls']:
            if '.dll' not in dll:
                dll = '{}.dll'.format(dll)
            dlls.append(dll)

        imps = v['imps']
        exps = v['exps']
        sections = v['sections']
        headers = v['headers']
        generics = v['generics']

        cols = dlls + imps + exps
        vals = [True] * (len(dlls) + len(imps) + len(exps))
        cols += ['api_import_nb', 'api_export_nb', 'dll_import_nb']
        vals += [len(imps), len(exps), len(dlls)]
        cols += list(sections.keys())
        vals += list(sections.values())
        cols += list(headers.keys())
        vals += list(headers.values())
        cols += list(generics.keys())
        vals += list(generics.values())
        df.loc[sample_id, cols] = vals
        if c % 1000 == 0:
            print(c)
        # print(c)

    return df


def get_all_features(res):
    IMPEXP_THR = 0.002
    all_features = {}
    cnt = Counter()
    for _, features in res.items():
        if 'features' in features:
            features = features['features']
        for f in features['generics']:
            all_features[f] = {'dtype': int, 'defval': 0}
        for f, _ in features['sections'].items():
            if 'name' in f:
                all_features[f] = {'dtype': object, 'defval': 'none'}
            elif 'characteristics' in f:
                all_features[f] = {'dtype': bool, 'defval': False}
            else:
                all_features[f] = {'dtype': int, 'defval': 0}

        for f, _ in features['headers'].items():
            all_features[f] = {'dtype': int, 'defval': 0}

        for f in features['dlls']:
            if not f.endswith('.dll'):
                f = '{}.dll'.format(f.split('.dll')[0])
            all_features[f] = {'dtype': bool, 'defval': False}

        for f in features['imps'] + features['exps']:
            cnt[f] += 1
            all_features[f] = {'dtype': bool, 'defval': False}

        for f in features['rich']:
            all_features[f] = {'dtype': int, 'defval': 0}

    for f in ['api_import_nb', 'api_export_nb', 'dll_import_nb']:
        all_features[f] = {'dtype': int, 'defval': 0}

    x = len(all_features)
    res = {}
    for f, v in all_features.items():
        if f.startswith('imp_') or f.startswith('exp_'):
            if cnt[f] >= IMPEXP_THR * len(res):
                res[f] = v
        else:
            res[f] = v
    all_features = res

    print("Out of {} features for the new samples, after removing the rare imp/exp features, we have {} features left".format(x, len(all_features)))

    return all_features

def extract_packer_samples(packer_name, samples_path, src):
    res = util.load_features_jsonfile(src, packer_name)

    df = util.load_wildlab_df()
    if df is None:
        df = util.load_wild_df()
        assert 'packer_name' in df.columns
        assert 'source' in df.columns
    # else:
        # util.backup_wildlab_df()

    data = []
    for dirpath, _, filenames in os.walk(samples_path):
        for filename in filenames:
            if filename.endswith('.bin'):
                if filename not in res:
                    filepath = os.path.join(dirpath, filename)
                    data.append(filepath)
    with multiprocessing.Pool() as p:
        tmp = p.map(extract_features_of_lab_sample, data)

    if len(tmp):
        res.update({filename: {'features': features, 'unpacked_sample_sha1': unpacked_sample_sha1, 'sample_sha1': sha1} for filename, unpacked_sample_sha1, sha1, features in tmp if unpacked_sample_sha1 != -1 and sha1 not in df})
        del tmp

        util.save_features_jsonfile(res, src, packer_name)

    tmp = len(res)
    sha1s = set(df.sample_sha1)
    res = {filename: v for filename, v in res.items() if v['sample_sha1'] not in sha1s}
    print("From {} packed samples by the {}, {} samples are not added to the dataframe yet".format(tmp, packer_name, len(res)))

    # Check if along the new packed samples, we have samples with same sha1s which means they must be corrupted in some way!!!
    c = Counter()
    for filename, v in res.items():
        c[v['sample_sha1']] += 1
    corrupted_sha1s = set([sha1 for sha1, cnt in c.items() if cnt > 1])
    tmp = len(res)
    res = {filename: v for filename, v in res.items() if v['sample_sha1'] not in corrupted_sha1s}
    print("FROM {} samples packed by the {}, {} samples have been corrupted prob.".format(tmp, packer_name, len(res)))

    # we might packed more samples than we need. we should avoid adding packed samples that the original version of them is not in the dataset anymore!
    tmp = len(res)
    res = {filename: v for filename, v in res.items() if v['unpacked_sample_sha1'] in sha1s}
    print("FROM {} samples packed by the {}, the original samples of {} samples are in the dataset!".format(tmp, packer_name, len(res)))
    if len(res) == 0:
        return

    features = get_all_features(res)
    df = init_cols(df, features)

    df = add_samples_of_packer_to_pickle_file(df, res, packer_name, src)

def add_ember_samples_to_wild():
    res = util.load_features_jsonfile(src='wild-ember')
    if not res:
        res = {}

    samples = []
    for dirpath, _, filenames in os.walk(util.get_ember_samples_root(malicious=True)):
        for filename in filenames:
            filepath = os.path.join(dirpath, filename)
            if filepath not in res:
                samples.append([filepath, True])

    for dirpath, _, filenames in os.walk(util.get_ember_samples_root(malicious=False)):
        for filename in filenames:
            filepath = os.path.join(dirpath, filename)
            if filepath not in res:
                samples.append([filepath, False])

    print("extracting features for {} samples".format(len(samples)))
    with multiprocessing.Pool() as p:
        tmp = p.map(extract_features_of_ember_sample, samples)

    if len(tmp):
        res.update({sample_path: {'features': features, 'sample_sha1': sample_sha1, 'label': label} for sample_path, sample_sha1, label, features in tmp})
        del tmp
        util.save_features_jsonfile(res, 'wild-ember')

    df = util.load_wild_df()

    res = {sample_path: v for sample_path, v in res.items() if v['features'] != -1}
    tmp = len(res)
    sha1s = set(df.sample_sha1)
    res = {filename: v for filename, v in res.items() if v['sample_sha1'] not in sha1s}
    print("From {} samples in the ember, {} samples are not added to the dataframe yet".format(tmp, len(res)))
    del sha1s, tmp

    features = get_all_features(res)
    df = init_cols(df, features)

    df = add_samples_of_ember_to_pickle_file(df, res)

def copy_ember_samples(res):
    for filename, v in res.items():
        sample_sha1 = v['sample_sha1']
        src = 'wild-ember'
        sample_new_path = util.get_sample_path(src=src, sample_sha1=sample_sha1)
        util.make_dir_for_file(sample_new_path)
        if os.path.exists(filename):
            shutil.move(filename, sample_new_path)

def extract_features_of_ember_sample(sample):
    sample_path, label = sample

    sample_sha1 = util.compute_sha1(sample_path)
    res = parse_pe(sample_path)
    if res:
        return [sample_path, sample_sha1, label, res]
    else:
        return [sample_path, sample_sha1, label, -1]


def extract_wild():
    res = util.load_features_jsonfile(src='wild')
    if not res:
        res = {}

    df = util.load_wildlab_df(strings=False)
    remain_df = df[~df.index.isin([int(k) for k in res.keys()])]
    data = []
    print("features already extracted for {} samples".format(len(res.keys())))
    print("still {} samples need to be processed".format(len(remain_df)))
    for sample_id, row in remain_df.iterrows():
        sample = row.to_dict()
        sample_id = str(sample_id)
        sha1 = sample['sample_sha1']
        sample_file = util.get_sample_path('wild', sha1)
        data.append([sample_id, sample_file])

    with multiprocessing.Pool() as p:
        tmp = p.map(extract_features_of_wild_sample, data)
    res.update({sample_id: features for sample_id, features in tmp if sample_id != -1})
    del tmp
    util.save_features_jsonfile(res, src='wild')

    df = df[df.index.isin([int(k) for k in res.keys()])]

    df = build_wild_pickle_file(df, res)
    util.save_wild_df(df)

if __name__ == '__main__':
    # add_ember_samples_to_wild()
    # extract_wild()
    extract_packer_samples(sys.argv[1], sys.argv[2], sys.argv[3])
