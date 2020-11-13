#!/bin/bash

export DISPLAY="192.168.100.252:0.0"
export SESSION_MANAGER=xfce
xrdb -load ~/.Xresources
nohup xfsettingsd 2>&1 > /dev/null 2>&1 &
nohup terminator 2>&1 > /dev/null 2>&1 &
