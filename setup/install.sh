#! /bin/sh
# proxycannon-wg


###################
# install software
###################
# update and install deps
apt update
# apt -y upgrade
apt -y install unzip git wireguard

# install terraform
wget -qO - terraform.gpg https://apt.releases.hashicorp.com/gpg | sudo gpg --dearmor -o /usr/share/keyrings/terraform-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/terraform-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/terraform.list
apt update
apt -y install terraform=1.2.2

# create directory for our aws credentials
mkdir /home/$SUDO_USER/.aws
touch /home/$SUDO_USER/.aws/credentials
cat << EOF >> /home/$SUDO_USER/.aws/credentials
[default]
aws_access_key_id = REPLACE_WITH_YOUR_OWN
aws_secret_access_key = REPLACE_WITH_YOUR_OWN
region = ap-southeast-1
EOF
chown -R $SUDO_USER:$SUDO_USER /home/$SUDO_USER/.aws


################
# update subnet id in variables.tf
################
MAC=`curl http://169.254.169.254/latest/meta-data/network/interfaces/macs/`
SUBNETID=`curl http://169.254.169.254/latest/meta-data/network/interfaces/macs/$MAC/subnet-id`
sed -i "s/subnet-XXXXXXXX/$SUBNETID/" ../nodes/aws/variables.tf


################
# setup wireguard
################
# copy wg server config
cp ./configs/server.conf /etc/wireguard/wg0.conf

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
sed -i "s|SERVER_PUB_KEY|$SERVER_PUB_KEY|" ./configs/client.conf
sed -i "s|CLIENT_PRIV_KEY|$CLIENT_PRIV_KEY|" ./configs/client.conf

# update client config with remote IP of control-server and keypair
EIP=`curl -s http://169.254.169.254/latest/meta-data/public-ipv4`
sed -i "s|SERVER_PUB_IP|$EIP|" ./configs/client.conf


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
ip rule add from 10.10.10.0/24 table loadb
# always snat from eth0
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

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
echo "####################### WireGuard Client Config [client.conf] ################################"
cat ./configs/client.conf

echo "####################### Be sure to add your AWS API keys and SSH keys to the following locations ###################"
echo "[!] copy your aws ssh private key to ~/.ssh/proxycannon.pem and chmod 600"
echo "[!] place your aws api id and key in ~/.aws/credentials"

echo "[!] remember to run 'terraform init' in the nodes/aws on first use"
