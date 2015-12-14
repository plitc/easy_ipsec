#!/bin/sh
### ### ### PLITC ### ### ###

screen -AdmS 'main' /github/easy_ipsec/docker.run.sh
screen -S 'main' -X screen bash -l
screen -r 'main'

### ### ### PLITC ### ### ###
# EOF
