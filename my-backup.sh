#!/bin/bash

TODAY=$(date +%d-%m-%Y)
BACKUPDIR="/superbig/backup"

sudo mkdir -p ${BACKUPDIR}/${HOSTNAME}

sudo rsync -azb \
    --delete \
    --backup-dir="${BACKUPDIR}/${HOSTNAME}/${TODAY}" \
    / \
    --exclude=dev/* \
    --exclude=proc/* \
    --exclude=sys/* \
    --exclude=backup/* \
    --exclude=mnt/* \
    --exclude=media/* \
    --exclude=snap/* \
    --exclude=var/lib/libvirt/images/* \
    --exclude=home/rafaeldtinoco/snap/* \
    ${BACKUPDIR}/${HOSTNAME}/latest

ret=$?

exit $ret
