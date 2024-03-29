FFS-Monitor on Debian Linux
###########################



# Updating System
# ---------------
apt-get update
apt-get upgrade
apt-get dist-upgrade


# Installing neccessary Modules
# -----------------------------
apt install haveged
apt install libpcap0.8
apt install mc
apt install fastd
apt install batctl
apt install iptables-persistent 

apt install python3-git
apt install python3-dnspython
apt install python3-psutil
apt install python3-shapely
apt install python3-scapy


if [ $(grep -c "batman_adv" /etc/modules) = 0 ]; then
  echo batman_adv >>/etc/modules
fi

/sbin/modprobe batman_adv


# Creating Working Folders
# ------------------------
mkdir -p /var/lib/ffs/git
mkdir -p /var/lib/ffs/keys
mkdir -p /var/lib/ffs/database
mkdir -p /var/lib/ffs/blacklist

mkdir -p /var/log/ffs
mkdir -p /var/log/ffs/monitor
mkdir -p /var/log/ffs/onboarder


# Setting up Git Repositories
# ---------------------------
if [ ! -d /var/lib/ffs/git/site-ffs ]; then
  git clone https://github.com/freifunk-stuttgart/site-ffs.git /var/lib/ffs/git/site-ffs
else
  ( cd /var/lib/ffs/git/site-ffs && git pull )
fi 

if [ ! -d /var/lib/ffs/git/peers-ffs ]; then
  git clone https://github.com/freifunk-stuttgart/peers-ffs /var/lib/ffs/git/peers-ffs
else
  ( cd /var/lib/ffs/git/peers-ffs && git pull )
fi 

if [ ! -d /var/lib/ffs/git/FFS-Tools ]; then
  git clone https://github.com/FFS-Roland/FFS-Tools.git /var/lib/ffs/git/FFS-Tools
else
  ( cd /var/lib/ffs/git/FFS-Tools && git pull )
fi 


# Creating Fastd-Keys
# -------------------
for seg in $(ls /var/lib/ffs/git/peers-ffs);
do
  if [ ! -e /var/lib/ffs/keys/$seg.key ]; then
    fastd --generate-key > /var/lib/ffs/keys/$seg.key
  fi
done


# Setting up network configuration for connection to FFS (Uplink) on Monitor01
# ----------------------------------------------------------------------------
/var/lib/ffs/git/FFS-Tools/Monitoring/create-ffs-uplink-config.py --monid 1 --siteconf /var/lib/ffs/git/site-ffs/site.conf  --vpnkeys /var/lib/ffs/keys --gitpeers /var/lib/ffs/git/peers-ffs

for seg in $(ls /var/lib/ffs/git/peers-ffs);
do
  git add /var/lib/ffs/git/peers-ffs/${seg}/peers/ffs-020039${seg/vpn/}ff01
  systemctl enable fastd@${seg}
done


# Setting up network configuration for connection to FFS (Uplink) on Monitor02
# ----------------------------------------------------------------------------
/var/lib/ffs/git/FFS-Tools/Monitoring/create-ffs-uplink-config.py --monid 2 --siteconf /var/lib/ffs/git/site-ffs/site.conf  --vpnkeys /var/lib/ffs/keys --gitpeers /var/lib/ffs/git/peers-ffs

for seg in $(ls /var/lib/ffs/git/peers-ffs);
do
  git add /var/lib/ffs/git/peers-ffs/${seg}/peers/ffs-020039${seg/vpn/}ff02
  systemctl enable fastd@${seg}
done


# Push fastd-Keys to Git
# ----------------------
git commit -a
git push

reboot    # for activation of new network configuration


# Filling Database with data from Git
# -----------------------------------
cp /var/lib/ffs/git/FFS-Tools/database/*  /var/lib/ffs/database
<edit> /var/lib/ffs/database/.Accounts.json


# Setting up program folder
# -------------------------
cp /var/lib/ffs/git/FFS-Tools/Monitoring/* /usr/local/bin


# Creating cron job for ffs-Check.sh
# ----------------------------------
crontab -e
5-55/10 * * * * /usr/local/bin/ffs-Check.sh    # Monitor01
0-50/10 * * * * /usr/local/bin/ffs-Check.sh    # Monitor02

/etc/init.d/cron reload


#<EOF>
