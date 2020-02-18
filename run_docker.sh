#!/bin/sh
HOMEDIR=/home/hojjat/packware/packware-release
docker run --rm -v $HOMEDIR/data:/packware/data -v $HOMEDIR/results:/packware/results -v $HOMEDIR/code:/packware/code -w /packware/code/experiments --name packware --user $(id -u):$(id -g) -it packware /bin/sh
