#!/bin/bash

TODAY=$(date +%Y-%m-%d)
BACKUPDIR="/superbig/backup"

compl=""

[[ $(($(date +%d)%10)) -ne 0 ]] && compl="--exclude=var/lib/libvirt/images/*"

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
    --exclude=home/rafaeldtinoco/snap/* \
    $compl \
    ${BACKUPDIR}/${HOSTNAME}/latest

ret=$?

exit $ret
