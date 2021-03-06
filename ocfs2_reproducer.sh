#!/bin/sh

set -e

DISK=/disk

cleanup () {
  umount /mnt || true
  [ "$LOOP" ] && losetup -d $LOOP
  rm -f $DISK $DISK.image || true
  # service o2cb stop
  sed -i -e 's/^O2CB_ENABLED=.*/O2CB_ENABLED=false/' /etc/default/o2cb
  echo cleanup
}

trap "cleanup" 0 2 3 15

# configure cluster
HOSTNAME=$(hostname)

cat >/etc/ocfs2/cluster.conf <<EOF
cluster:
        node_count = 1
        name = ocfs2

node:
        ip_port = 7777
        ip_address = 127.0.0.1
        number = 0
        name = $HOSTNAME
        cluster = ocfs2
EOF

# start cluster
sed -i -e 's/^O2CB_ENABLED=.*/O2CB_ENABLED=true/' /etc/default/o2cb
service o2cb restart

# check cluster
echo "=== dlmfs ==="
grep '^ocfs2_dlmfs /dlm' /proc/mounts

echo "=== lsmod ==="
lsmod | grep ocfs2_stack_o2cb

echo "=== o2hbmonitor ==="
pgrep -a o2hbmonitor

# print info
echo "=== o2cluster ==="
o2cluster -r

echo "=== o2cb_ctl ==="
o2cb_ctl -I -n $HOSTNAME

# create test disk
echo "=== losetup ==="
dd if=/dev/zero of=$DISK bs=1M count=200 2>&1
LOOP=$(losetup --find --show $DISK)

# test tools
echo "=== mkfs ==="
mkfs.ocfs2 --cluster-stack=o2cb --cluster-name=ocfs2 $LOOP 2>&1

# echo "=== o2image ==="
# o2image $LOOP $DISK.image
# ls -l $DISK.image

# echo "=== fsck ==="
# fsck.ocfs2 -f -y $LOOP 2>&1

# echo "=== o2cluster ==="
# o2cluster -o $LOOP

# echo "=== tunefs ==="
# tunefs.ocfs2 -L $DISK -N 3 -Q 'Label = %V\nNumSlots = %N\n' $LOOP

# echo "=== debugfs ==="
# debugfs.ocfs2 -R stats $LOOP

# echo "=== o2info ==="
# o2info --volinfo $LOOP

# echo "=== grow ==="
# dd if=/dev/zero of=$DISK bs=1M count=50 seek=200 2>&1
# losetup --set-capacity $LOOP
# tunefs.ocfs2 -S $LOOP

echo "=== mount ==="
mount $LOOP /mnt
df /mnt

# echo "=== mounted ==="
# mounted.ocfs2 -d
# mounted.ocfs2 -f

# echo "=== defragfs ==="
# cp -a /bin /mnt
# defragfs.ocfs2 -v /mnt
