#!/bin/bash

[ $UID != 0 ] && { echo "you are not root :P"; exit 1; }

systemctl restart iscsid.service

iscsi01_ip=$(ip -4 -o addr show iscsi01 | sed -r 's:.* (([0-9]{1,3}\.){3}[0-9]{1,3})/.*:\1:')
# iscsi02_ip=$(ip -4 -o addr show iscsi02 | sed -r 's:.* (([0-9]{1,3}\.){3}[0-9]{1,3})/.*:\1:')

iscsi01_mac=$(ip -o link show iscsi01 | sed -r 's:.*\s+link/ether (([0-f]{2}(\:|)){6}).*:\1:g')
# iscsi02_mac=$(ip -o link show iscsi02 | sed -r 's:.*\s+link/ether (([0-f]{2}(\:|)){6}).*:\1:g')

iscsiadm -m iface -I iscsi01 --op=new
iscsiadm -m iface -I iscsi01 --op=update -n iface.hwaddress -v $iscsi01_mac
iscsiadm -m iface -I iscsi01 --op=update -n iface.ipaddress -v $iscsi01_ip

# iscsiadm -m iface -I iscsi02 --op=new
# iscsiadm -m iface -I iscsi02 --op=update -n iface.hwaddress -v $iscsi02_mac
# iscsiadm -m iface -I iscsi02 --op=update -n iface.ipaddress -v $iscsi02_ip

systemctl restart iscsid.service

iscsiadm -m discovery -I iscsi01 --op=new --op=del --type sendtargets --portal storage.iscsi01
# iscsiadm -m discovery -I iscsi02 --op=new --op=del --type sendtargets --portal storage.iscsi02

iscsiadm -m node --op=update -n node.startup -v automatic
iscsiadm -m node --op=update -n node.conn[0].startup -v automatic

systemctl restart iscsid.service

iscsiadm -m node --loginall=automatic
