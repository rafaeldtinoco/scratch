#!/bin/bash

set -e

interfaces=()

interfaces+=( iscsi01 )
# interfaces+=( iscsi02 )
interfaces+=( private01 )
# interfaces+=( private02 )
interfaces+=( public01 )
# interfaces+=( public02 )

netprefix=()

netprefix+=( "10.250.94" )
# netprefix+=( "10.250.93" )
netprefix+=( "10.250.96" )
# netprefix+=( "10.250.95" )
netprefix+=( "10.250.92" )
# netprefix+=( "10.250.91" )

for ((i=0; i<10; i++))
do
    ip addr show eth$i && sudo dhclient eth$i
done

originalnic=()

for ((i=0; i<${#interfaces[@]}; i++))
do
    int=$(ip -4 -o addr show | grep ${netprefix[$i]} | awk '{print $2}')
    originalnic+=( $int )
done

macaddress=()

for ((i=0; i<${#interfaces[@]}; i++))
do
    mac=$(ip -0 -o addr show ${originalnic[$i]} | awk '{print $15}')
    macaddress+=( $mac )
done


# systemd-networkd .link files

for ((i=0; i<${#interfaces[@]}; i++))
do
    {
        echo "[Match]"
        echo "# ${originalnic[$i]}"
        echo "MACAddress=${macaddress[$i]}"
        echo ""
        echo "[Link]"
        echo "Name=${interfaces[$i]}"
    } | sudo tee /etc/systemd/network/10-${interfaces[$i]}.link

done

# systemd-networkd .network files

for ((i=0; i<${#interfaces[@]}; i++))
do
    {
        echo "[Match]"
        echo "# ${originalnic[$i]}"
        echo "Name=${interfaces[$i]}"
        echo ""
        echo "[Network]"
        echo "DHCP=ipv4"
        echo ""
        echo "[DHCPv4]"
        echo "UseDNS=false"
        echo "UseNTP=false"
        echo "UseRoutes=false"
        echo "ClientIdentifier=mac"
    } | sudo tee /etc/systemd/network/20-${interfaces[$i]}.network

done
