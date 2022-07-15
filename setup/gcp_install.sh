#! /bin/sh
# proxycannon-wg


######################
# install dependencies
######################
# update and install deps
apt update
# apt -y upgrade
apt -y install git wireguard python3-pip
pip3 install google-cloud-compute google-auth


################
# setup wireguard
################
# copy wg server config
cp ./configs/gcp_server.conf /etc/wireguard/wg0.conf

# generate server keypair
wg genkey | sudo tee /etc/wireguard/server.key
SERVER_PRIV_KEY=`cat /etc/wireguard/server.key`
chmod go= /etc/wireguard/server.key
cat /etc/wireguard/server.key | wg pubkey | sudo tee /etc/wireguard/server.pub
SERVER_PUB_KEY=`cat /etc/wireguard/server.pub`

# generate client keypair
wg genkey | tee /etc/wireguard/client.key
CLIENT_PRIV_KEY=`cat /etc/wireguard/client.key`
cat /etc/wireguard/client.key | wg pubkey | tee /etc/wireguard/client.pub
CLIENT_PUB_KEY=`cat /etc/wireguard/client.pub`

# update server config with keypair
sed -i "s|SERVER_PRIV_KEY|$SERVER_PRIV_KEY|" /etc/wireguard/wg0.conf
sed -i "s|CLIENT_PUB_KEY|$CLIENT_PUB_KEY|" /etc/wireguard/wg0.conf

# update client config with keypair
sed -i "s|SERVER_PUB_KEY|$SERVER_PUB_KEY|" ./configs/gcp.conf
sed -i "s|CLIENT_PRIV_KEY|$CLIENT_PRIV_KEY|" ./configs/gcp.conf

# update client config with remote IP of control-server and keypair
EIP=`curl -H "Metadata-Flavor: Google" http://metadata/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip`
sed -i "s|SERVER_PUB_IP|$EIP|" ./configs/gcp.conf


###################
# setup networking
###################
# setup routing and forwarding
sysctl -w net.ipv4.ip_forward=1

# use L4 (src ip, src dport, dest ip, dport) hashing for load balancing instead of L3 (src ip ,dst ip)
#echo 1 > /proc/sys/net/ipv4/fib_multipath_hash_policy
sysctl -w net.ipv4.fib_multipath_hash_policy=1

# setup a second routing table
echo "50      loadb" >> /etc/iproute2/rt_tables

# set rule for WireGuard client source network to use the second routing table
ip rule add from 10.10.20.0/24 table loadb
# always snat from ens4
iptables -t nat -A POSTROUTING -o ens4 -j MASQUERADE

# start service
systemctl start wg-quick@wg0.service


#################################
# post installation instructions
#################################

echo "Copy ~/client.conf to your workstation."
echo "You can run the following command to download the file to your workstation (include the trailing period):"
echo 
echo "scp -i proxycannon.pem ubuntu@$EIP:/home/ubuntu/proxycannon-wg/setup/configs/client.conf ."
echo 
echo "####################### WireGuard Client Config [gcp.conf] ################################"
cat ./configs/gcp.conf
