# When Malware is Packin’ Heat; Limits of Machine Learning Classifiers Based on Static Analysis Features
## Contents

[1. Introduction](#1-introduction)

[2. Dataset](#2-dataset)

[3. Docker](#3-docker)

[4. Experiments](#4-experiments)

## 1. Introduction
This repository provides datasets and codes that are needed to reproduce the experiments in the paper [When Malware is Packin’ Heat; Limits of Machine Learning Classifiers Based on Static Analysis Features](https://github.com/ucsb-seclab/packware). You can find the presention of our work [here](https://youtu.be/hMIEKFrRA-s).

In this paper, we have investigated the following question: does static analysis on packed binaries provide a rich enough set of features to a malware classifier? We first observed that the distribution of the packers in the training set must be considered, otherwise the lack of overlap between packers used in benign and malicious samples might cause the classifier to distinguish between packing routines instead of behaviors. Different from what is commonly assumed, packers preserve information when packing programs that is “useful” for malware classification, however, such information does not necessarily capture the sample’s behavior. In addition, such information does not help the classifier to (1) generalize its knowledge to operate on previously unseen packers, and (2) be robust against trivial adversarial attacks. We observed that static machine-learning-based products on VirusTotal produce a high false positive rate on packed binaries, possibly due to the limitations discussed in this work. This issue becomes magnified as we see a trend in the anti-malware industry toward an increasing deployment of machine-learning-based classifiers that only use static features.

If you find this work useful for your research you may want cite our paper.
```
TO BE FILLED LATER.
```

## 2. Dataset
We create and use two different datasets in this work, named Wild Dataset and Lab Dataset.
The former contains executables found in the wild, from two sources, an anti-malware vendor, and EMBER Dataset.
We created the latter by packing executables in the wild with a set of nine packers.
We exploited a wide range of techniques, especially dynamic analysis, to determine whether each sample is (1) benign or malicious and (2) packed or not packed.
For details, you may read the paper (Section IV).

All these two datasets are stored in a single pickle file (using pandas package). Column ```source``` determines the source of each sample, ```wild``` and ```wild-ember``` mean the sample has been seen in the wild, by the anti-malware vendor or Endgame, and ```lab``` means we have created the sample by packing a sample from Wild Dataset.
```packed``` column determines if the sample is packed or not. ```malicious``` column determines if the sample is malicious or not. ```packer_name``` determines the packer which is used to pack the sample, ```none``` is set for unpacked samples. For samples from Lab Dataset, the column ```unpacked_sample_sha1``` determines the sha1sum of the executable before packing. This might be helpful for some experiments, as we are able to track back the history of the sample. In general, the name of the columns should be self-descriptive.

To download the pickle file, navigate to [this url](https://drive.google.com/file/d/1PMCHM46mc4lhjMczfIDP45w_LGKTea8q/view?usp=sharing) or [install gdrive](https://github.com/odeke-em/drive/releases) and run the following commands (NOTE: you will need to use a web browser to authorize gdrive to use your credentials):
```sh
mkdir data
cd data/
drive init
# ... copy authorization url to your browser ...
drive pull -id 1PMCHM46mc4lhjMczfIDP45w_LGKTea8q # md5sum: 8e692830252339d4a9410959e0607e71
```
To download only Wild Dataset, navigate to [this url](https://drive.google.com/file/d/1stVX2-APaiH9XvXhVpySMkRmnLqsSCLM/view?usp=sharing) or [install gdrive](https://github.com/odeke-em/drive/releases) and run the following commands (see NOTE above):
```sh
mkdir data
cd data/
drive init
# ... copy authorization url to your browser ...
drive pull -id 1stVX2-APaiH9XvXhVpySMkRmnLqsSCLM # md5sum: 2afe2fb2a04ac96fe004983db0121c80
```

To download the samples, please contact us. We have all the samples on our server, and we are happy to share it with the community. We do our best to make this process smooth. Unfortunately, there are always serious legitimate concerns with putting this huge number of malware samples in the wild.
As we fully explained in the paper, we used Cuckoo and Deep Packer Inspection tools to create our datasets. All the file related to this process, including the dynamic behavior of samples are available on demand. We are happy to provide that also.
We also can provide the VirusTotal reports for all the executables in our datasets.
Please read [here](https://github.com/ucsb-seclab/packware/blob/master/datasets/README.md) before contacting us.
## 3. Docker
In order to use our source code in the docker image, you first need to properly install Docker.
To download the docker image that we used for our experiments, navigate to [this url](https://drive.google.com/file/d/1c7lOFLIf4rA2HRqfdRaEvYsbTSRlTjwE/view?usp=sharing) or [install gdrive](https://github.com/odeke-em/drive/releases) and run the following commands:
```sh
drive init
# ... copy authorization url to your browser ...
drive pull -id 1c7lOFLIf4rA2HRqfdRaEvYsbTSRlTjwE # md5sum: 1e198bfd8ca37a5f49d0b380e85234d2
```
Then, to load and run the container:
```console
$ ./load_image.sh packware-docker.tar
$ ./run_docker.sh
```
Now, you can run all the experiments.
## 4. Experiments
You need to execute the following scripts in ```code/experiments``` directory. Roughly speaking, each experiment uses one configuration file (starts with ```config*.py```) and the main training file (training.py or training-nn.py for neural network).
In ```config*.py```, ```round``` means how many times we run an experiments. It is just for collecting more coherent results, it has set to five in our experiments.
We know the code is not very well-written, and we are happy to answer all the questions.

Run the following commands for the experiments in the paper (with the same order as in the paper).
```
./exp_nopacked-benign.sh
```

To run Experiment "packer classifier", run:
```
python packerclassifier.py
```

To run Experiment "good-bad packers", run:
```
python run_goodbadpackers_allcombs.py
```
```
./exp_diffPackedBenign.sh
./exp_diffPackedBenignNN.sh # for neural network
```
```
./exp_labDiffPackedBenign.sh
./exp_labDiffPackedBenignNN.sh # for neural network
```
```
./exp_singlepacker.sh
./exp_singlepacker-onlyapiimport.sh
./exp_singlepacker-onlyheader.sh
./exp_singlepacker-onlyrich.sh
./exp_singlepacker-onlysections.sh
```
```
./exp_wildvspacker.sh
./exp_wildvspacker-rich.sh
./exp_wildvspacker-nn.sh # for neural network
```
```
./exp_withheldpacker.sh
./exp_withheldpacker-nongrams.sh
./exp_withheldpacker-nn.sh # for neural network
```
```
./exp_labagainstwild.sh
```
```
./exp_dolphin.sh #  Strong & Complete Encryption
```

For the adversarial experiment, use ```code/experiments/adversarial/adv.py``` script.
