import json

respath = '../../../results/paper/experiments/exp-adversarial/malconfs-adv.json'
with open(respath) as f:
    res = json.load(f)

minChanges = 0
maxChanges = 0
succ = 0
succWithHighConf = 0

for sample_id, r in res.items():
    if r['finalConf'] >= 0.9:
        succWithHighConf += 1
        succ += 1
        minChanges += r['minChanges']
        maxChanges += r['maxChanges']
    elif r['finalConf'] >= 0.5:
        succ += 1
        minChanges += r['minChanges']

minChangesMean = (minChanges * 1.0) / succ
maxChangesMean = (maxChanges * 1.0) / succWithHighConf

print("Out of {} samples, we successfully generated adv. samples for {} samples, with high confidence for {} samples".format(len(res), succ, succWithHighConf))
print("{} steps were enough for flipping the detection".format(minChangesMean))
print("{} steps were enough for flipping the detection with confidence of 0.9".format(maxChangesMean))
