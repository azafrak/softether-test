#!/bin/bash



SERVER_IP=$(dig @resolver4.opendns.com myip.opendns.com +short)
SERVER_PASSWORD="hacker542"
USER="azafrak"
USER_PASSWORD="hacker542"
HUB="VPN"
SHARED_KEY="Taz2206"
IP_START="10.10.0.10"
IP_END="10.10.0.250"
IP_LOCAL="10.10.0.1"
IP_MASK="10.10.0.0/24"
DNS1="8.8.8.8"
DNS2="8.8.4.4"


#set version to download
latest=$(wget -q -O - https://www.softether-download.com/files/softether/ | grep -P -i -o '(?<=href="\/files\/softether\/)(v\d+.\d+-\d+-rtm-\d{4}.\d{2}.\d{2})' | tail -1)
#latest="v4.37-9758-beta-2021.08.16"
arch="64bit_-_Intel_x64_or_AMD64"
arch2="x64-64bit"

#generate url to download
file="softether-vpnserver-"$latest"-linux-"$arch2".tar.gz"
link="http://www.softether-download.com/files/softether/"$latest"-tree/Linux/SoftEther_VPN_Server/"$arch"/"$file

function checkupdate(){
	if ! command -v dialog &> /dev/null
	then
		echo "updating system"
		updatesystem
	else
		echo "system already updated"
	fi
}

function updatesystem(){
	echo "starting.."
	apt-get update -y
	apt-get upgrade -y
	apt-get install build-essential gnupg2 gcc make git dialog -y
	apt-get install --install-recommends linux-generic-hwe-20.04 -y 
	apt-get install dnsmasq fail2ban iftop traceroute -y
	apt-get install iptables-persistent -y
}

function installvpnserver(){
	LMENU_TITLE="Softether Installer"
	INISECTION="Settings"
	dialog --backtitle "Exit $LMENU_TITLE" --title "$LMENU_TITLE (${SERVER_IP})" \
	--form "\nEnter Settings and Select OK" 20 70 7 \
	"Server Password:" 1 1 "$SERVER_PASSWORD" 1 20 20 20  \
	"new user:" 2 1 "$USER" 2 20 20 20  \
	"user pass:" 3 1 "$USER_PASSWORD" 3 20 20 20  \
	"HUB:" 4 1 "$HUB" 4 20 20 20  \
	"Shared Key:" 5 1 "$SHARED_KEY" 5 20 20 20  \
	"Local IP:" 6 1 "$IP_LOCAL" 6 20 20 20  \
	"Start IP:" 7 1 "$IP_START" 7 20 20 20  \
	"End IP:" 8 1 "$IP_END" 8 20 20 20  \
	"IP Mask:" 9 1 "$IP_MASK" 9 20 20 20  \
	"DNS1:" 10 1 "$DNS1" 10 20 20 20  \
	"DNS2:" 11 1 "$DNS2" 11 20 20 20  \
	> /tmp/out.tmp \
	2>&1 >/dev/tty
	MENUSELECTION=$? #1 cancel, 0-ok, 255-esc
	# Start retrieving each line from temp file 1 by one with sed and declare variables as inputs
	SERVER_PASSWORD=`sed -n 1p /tmp/out.tmp`
	USER=`sed -n 2p /tmp/out.tmp`
	USER_PASSWORD=`sed -n 3p /tmp/out.tmp`
	HUB=`sed -n 4p /tmp/out.tmp`
	SHARED_KEY=`sed -n 5p /tmp/out.tmp`
	IP_LOCAL=`sed -n 6p /tmp/out.tmp`
	IP_START=`sed -n 7p /tmp/out.tmp`
	IP_END=`sed -n 8p /tmp/out.tmp`
	IP_MASK=`sed -n 9p /tmp/out.tmp`
	DNS1=`sed -n 10p /tmp/out.tmp`
	DNS2=`sed -n 11p /tmp/out.tmp`

	# remove temporary file created
	rm -f /tmp/out.tmp
	#Write to output file the result
	#echo $input1 , $input2 , $input3 , $input4 , $input5 
	if [ "$MENUSELECTION" == "0" ]; then 
		startInstall
	else
		echo "no selection made"
	fi
}

function startInstall(){
	clear
	rm -rf $file
	echo "Downloading $file"
	wget "$link"
	if [ -f "$file" ];then
		rm -rf vpnserver
		tar xzf "$file"
		dir=$(pwd)
		echo "current dir " $dir
		cd vpnserver
		dir=$(pwd)
		echo "changed to dir " $dir
	else
		echo "Archive not found. Please rerun this script or check permission."
		break
	fi

	echo "compiling vpn server"
	make
	cd .. 
	rm -rf /usr/local/vpnserver
	mv vpnserver /usr/local
	cd /usr/local/vpnserver
	chmod 600 *
	chmod 700 vpnserver
	chmod 700 vpncmd

	clear
	echo "running vpnserver"
	killall vpnserver
	./vpnserver stop
	rm -rf vpn_server.config
	rm -rf backup.vpn_server.config
	./vpnserver start 
	sleep 5
	clear
	echo "setting server password"
	./vpncmd localhost /SERVER /CSV /CMD ServerPasswordSet ${SERVER_PASSWORD}
	sleep 3
	echo "deleting default hub"
	./vpncmd localhost /SERVER /PASSWORD:${SERVER_PASSWORD} /CMD HubDelete DEFAULT
	echo "creating hub $(HUB)"
	./vpncmd localhost /SERVER /PASSWORD:${SERVER_PASSWORD} /CMD HubCreate ${HUB} /PASSWORD:${SERVER_PASSWORD}
	echo "creating user $(USER)"
	./vpncmd localhost /SERVER /PASSWORD:${SERVER_PASSWORD} /HUB:${HUB} /CMD UserCreate ${USER} /GROUP:none /REALNAME:none /NOTE:none
	echo "setting user password"
	./vpncmd localhost /SERVER /PASSWORD:${SERVER_PASSWORD} /HUB:${HUB} /CMD UserPasswordSet ${USER} /PASSWORD:${USER_PASSWORD}
	echo "enabling ipsec, l2tp and psk"
	./vpncmd localhost /SERVER /PASSWORD:${SERVER_PASSWORD} /CMD IPsecEnable /L2TP:yes /L2TPRAW:no /ETHERIP:no /PSK:${SHARED_KEY} /DEFAULTHUB:${HUB}
	echo "creating bridge"
	./vpncmd localhost /SERVER /PASSWORD:${SERVER_PASSWORD} /CMD BridgeCreate ${HUB} /DEVICE:soft /TAP:yes ${HUB}
	#./vpncmd localhost /SERVER /PASSWORD:${SERVER_PASSWORD} /CMD DhcpSet /START:192.168.30.10 /END:192.168.30.10 /MASK:255.255.255.0 /EXPIRE:7200 /GW:none /DNS:192.168.30.1 /DNS2:8.8.8.8 /DOMAIN:none /LOG:yes /PUSHROUTE:none
	#./vpncmd localhost /SERVER /PASSWORD:${SERVER_PASSWORD} /CMD VpnOverIcmpDnsEnable /ICMP:yes /DNS:yes
	#./vpncmd localhost /SERVER /PASSWORD:${SERVER_PASSWORD} /CMD SecureNatEnable
	#./vpncmd localhost /SERVER /PASSWORD:${SERVER_PASSWORD} /CMD ServerCertRegenerate [CN]
	#./vpncmd localhost /SERVER /PASSWORD:${SERVER_PASSWORD} /CMD ServerCertGet cert.cer
	#./vpncmd localhost /SERVER /PASSWORD:${SERVER_PASSWORD} /CMD SstpEnable yes
	#./vpncmd localhost /SERVER /PASSWORD:${SERVER_PASSWORD} /CMD OpenVpnEnable yes /PORTS:1194
	#./vpncmd localhost /SERVER /PASSWORD:${SERVER_PASSWORD} /CMD OpenVpnMakeConfig my_openvpn_config.zip
	#cp my_openvpn_config.zip ~/

	#echo "net.ipv4.ip_forward = 1" >>/etc/sysctl.conf
	echo "configuring autostart service"
	rm -rf /etc/init.d/vpnserver
	wget -P /etc/init.d https://bitbucket.org/serkanp/softethetubuntu20/raw/master/vpnserver.sh
	mv /etc/init.d/vpnserver.sh /etc/init.d/vpnserver
	mkdir /var/lock/subsys
	chmod 755 /etc/init.d/vpnserver

	echo "enabling service"
	update-rc.d vpnserver defaults

	echo "starting service"
	/etc/init.d/vpnserver start

	setIP

	echo "configuring firewall"
	ufw allow 22/tcp
	ufw allow 4422/tcp
	ufw allow 443/tcp
	ufw allow 5555/tcp
	ufw allow 992/tcp
	ufw allow 1194/udp
	echo "y" | ufw enable
	echo "please reboot"
	sleep 3

}

function checkvpnserver(){
	if [ -d "/usr/local/vpnserver" ]; then
	  # Take action if $DIR exists. #
	  echo "vpn server already exists"
	fi
}

function checkOS(){
	if [ -f /etc/os-release ]; then
		# freedesktop.org and systemd
		. /etc/os-release
		OS=$NAME
		VER=$VERSION_ID
	elif type lsb_release >/dev/null 2>&1; then
		# linuxbase.org
		OS=$(lsb_release -si)
		VER=$(lsb_release -sr)
	elif [ -f /etc/lsb-release ]; then
		# For some versions of Debian/Ubuntu without lsb_release command
		. /etc/lsb-release
		OS=$DISTRIB_ID
		VER=$DISTRIB_RELEASE
	elif [ -f /etc/debian_version ]; then
		# Older Debian/Ubuntu/etc.
		OS=Debian
		VER=$(cat /etc/debian_version)
	elif [ -f /etc/SuSe-release ]; then
		# Older SuSE/etc.
		...
	elif [ -f /etc/redhat-release ]; then
		# Older Red Hat, CentOS, etc.
		...
	else
		# Fall back to uname, e.g. "Linux <version>", also works for BSD, etc.
		OS=$(uname -s)
		VER=$(uname -r)
	fi
	case $(uname -m) in
	x86_64)
		BITS=64
		;;
	i*86)
		BITS=32
		;;
	*)
		BITS=?
		;;
	esac
	ARCH=$(uname -m)
	echo "OS=$OS, VER=$VER"
	if [ $OS == "Ubuntu" ]; then 
		echo "System is ubuntu"
	else
		echo "this script only designed for ubuntu"
		exit
	fi
}

function menu(){
 HEIGHT=15
WIDTH=50
CHOICE_HEIGHT=10
BACKTITLE="Main Menu"
TITLE="Welcome to Softether Installer"
MENU="Choose one of the following options:"
MENUSELECTION=1 
SLEEP_PERIOD=2
OPTIONS=(
		"c" "Clean Install Softether"
		"u" "Uninstall SoftEther"
		"u" "Update VPN Server"
		"a" "Add Hub"
		"e" "Add User"
		"s" "Change SSH Port"
		"r" "Restart VPN Server"
        q "Exit Q")
		
	CHOICE=$(dialog --clear \
					--backtitle "$BACKTITLE" \
					--title "$TITLE" \
					--menu "($OS $VER ${BITS}bit $ARCH)\n$MENU" \
					$HEIGHT $WIDTH $CHOICE_HEIGHT \
					"${OPTIONS[@]}" \
					2>&1 >/dev/tty)

	clear
	case $CHOICE in
			c)
				installvpnserver
				menu
				;;
			u)
				#update vpn server
				autoupdate
				;;
			a)
				#add hub
				creathub
				menu
				;;
			u)
				#uninstall softether
				clear
				uninstall
				
				;;
			e)
				#Add User
				clear
				createuser
				menu
				;;
			s)
				#change ssh port
				changeSSHPort
				menu
				;;
			r)
				#restart vpn server
				restartvpn
				;;
			3)
				echo "Bye"; break;;
	esac
}

function changeSSHPort(){

CHOICE=$(dialog --title "Change SSH Port" --clear \
					--inputbox "Please enter new Port" \
					16 51 2>&1 >/dev/tty)
	MENUSELECTION=$? #1 cancel, 0-ok, 255-esc
	if [ "$MENUSELECTION" == "0" ]; then 
		echo "selected port $CHOICE"
		sed -i "s/^#Port.*/Port ${CHOICE}/g" /etc/ssh/sshd_config
		sed -i "s/^Port.*/Port ${CHOICE}/g" /etc/ssh/sshd_config
		systemctl restart sshd
		echo "port changed , please logoff and logon again"
	else
		echo "no selection made"
	fi
}

function setIP(){
mv /etc/dnsmasq.conf /etc/dnsmasq.conf.old
touch /etc/dnsmasq.conf
cat <<EOF >> /etc/dnsmasq.conf
port=0
interface=tap_soft
dhcp-range=tap_soft,${IP_START},${IP_END},12h
dhcp-option=tap_soft,3,${IP_LOCAL}
dhcp-option=tap_soft,6,${DNS1},${DNS2}
EOF


#clear iptables 
resetIPTables
echo "setting new iptables rules"
#set new iptables
iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -s ${IP_MASK} -j ACCEPT
iptables -A FORWARD -j REJECT
iptables -t nat -A POSTROUTING -s ${IP_MASK} -j SNAT --to-source ${SERVER_IP}
echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
iptables-save > /etc/iptables/rules.v4
sed -i "s/^TAP_ADDR.*/TAP_ADDR=${IP_LOCAL}/g" /etc/init.d/vpnserver
echo "restarting services"
restartvpn

#upgrarde kernel and active TCP BBR Congestion Control and IPv4 Forwarding
if  grep -q "net.ipv4.ip_forward" "/etc/sysctl.d/ipv4_forwarding.conf" ; then
         sed -i "s/^net.ipv4.ip_forward.*/net.ipv4.ip_forward = 1/g" /etc/sysctl.d/ipv4_forwarding.conf
else
         echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.d/ipv4_forwarding.conf
fi
if  grep -q "net.core.default_qdisc" "/etc/sysctl.conf" ; then
         sed -i "s/^net.core.default_qdisc.*/net.core.default_qdisc=fq/g" /etc/sysctl.conf
else
	echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
fi
if  grep -q "net.ipv4.tcp_congestion_control" "/etc/sysctl.conf" ; then
         sed -i "s/^net.ipv4.tcp_congestion_control.*/net.ipv4.tcp_congestion_control=bbr/g" /etc/sysctl.conf
else
	echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
fi



}

function restartvpn(){
	update-rc.d vpnserver defaults
	service dnsmasq restart
	service vpnserver restart
}

function createuser(){
	LMENU_TITLE="Add User"
	INISECTION="Settings"
	dialog --backtitle "Exit $LMENU_TITLE" --title "$LMENU_TITLE (${SERVER_IP})" \
	--form "\nEnter Settings and Select OK" 20 70 7 \
	"Server Password:" 1 1 "$SERVER_PASSWORD" 1 20 20 20  \
	"new user:" 2 1 "$USER" 2 20 20 20  \
	"user pass:" 3 1 "$USER_PASSWORD" 3 20 20 20  \
	"HUB:" 4 1 "$HUB" 4 20 20 20  \
	> /tmp/out.tmp \
	2>&1 >/dev/tty
	MENUSELECTION=$? #1 cancel, 0-ok, 255-esc
	# Start retrieving each line from temp file 1 by one with sed and declare variables as inputs
	SERVER_PASSWORD=`sed -n 1p /tmp/out.tmp`
	USER=`sed -n 2p /tmp/out.tmp`
	USER_PASSWORD=`sed -n 3p /tmp/out.tmp`
	HUB=`sed -n 4p /tmp/out.tmp`

	# remove temporary file created
	rm -f /tmp/out.tmp
	#Write to output file the result
	#echo $input1 , $input2 , $input3 , $input4 , $input5 
	if [ "$MENUSELECTION" == "0" ]; then 
		cd /usr/local/vpnserver
		echo "creating user $(USER)"
		./vpncmd localhost /SERVER /PASSWORD:${SERVER_PASSWORD} /HUB:${HUB} /CMD UserCreate ${USER} /GROUP:none /REALNAME:none /NOTE:none
		echo "setting user password"
		./vpncmd localhost /SERVER /PASSWORD:${SERVER_PASSWORD} /HUB:${HUB} /CMD UserPasswordSet ${USER} /PASSWORD:${USER_PASSWORD}
		sleep 2
	else
		echo "no selection made"
	fi
	
}
function creathub(){
	LMENU_TITLE="Add User"
	INISECTION="Settings"
	dialog --backtitle "Exit $LMENU_TITLE" --title "$LMENU_TITLE (${SERVER_IP})" \
	--form "\nEnter Settings and Select OK" 20 70 3 \
	"Server Password:" 1 1 "$SERVER_PASSWORD" 1 20 20 20  \
	"HUB:" 2 1 "$HUB" 2 20 20 20  \
	> /tmp/out.tmp \
	2>&1 >/dev/tty
	MENUSELECTION=$? #1 cancel, 0-ok, 255-esc
	# Start retrieving each line from temp file 1 by one with sed and declare variables as inputs
	SERVER_PASSWORD=`sed -n 1p /tmp/out.tmp`
	HUB=`sed -n 2p /tmp/out.tmp`

	# remove temporary file created
	rm -f /tmp/out.tmp
	#Write to output file the result
	#echo $input1 , $input2 , $input3 , $input4 , $input5 
	if [ "$MENUSELECTION" == "0" ]; then 
		cd /usr/local/vpnserver
		echo "creating hub $(HUB)"
		./vpncmd localhost /SERVER /PASSWORD:${SERVER_PASSWORD} /CMD HubCreate ${HUB} /PASSWORD:${SERVER_PASSWORD}
		sleep 2
	else
		echo "no selection made"
	fi

}

function uninstall(){
	resetIPTables
	echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
	echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
	iptables-save > /etc/iptables/rules.v4
	service dnsmasq stop
	service vpnserver stop
	systemctl disable vpnserver
	systemctl disable dnsmasq
	rm -rf /etc/init.d/vpnserver
	rm -rf /usr/local/vpnserver
	ufw delete allow 443/tcp
	ufw delete allow 5555/tcp
	ufw delete allow 992/tcp
	ufw delete allow 1194/udp
	echo "y" | ufw enable
	echo "please restart server"
}

function resetIPTables(){
	echo "clearing iptables"
	iptables -P INPUT ACCEPT
	iptables -P FORWARD ACCEPT
	iptables -P OUTPUT ACCEPT
	iptables -t nat -F
	iptables -t mangle -F
	iptables -F
	iptables -X
}

#function autoupdate(){
#	latest=$(wget -q -O - https://www.softether-download.com/files/softether/ | grep -P -i -o '(?<=href="\/files\/softether\/)(v\d+.\d+-\d+-rtm-\d{4}.\d{2}.\d{2})' | tail -1)
#	arch="64bit_-_Intel_x64_or_AMD64"
#	arch2="x64-64bit"
#
#	#generate url to download
#	file="softether-vpnserver-"$latest"-linux-"$arch2".tar.gz"
#	link="http://www.softether-download.com/files/softether/"$latest"-tree/Linux/SoftEther_VPN_Server/"$arch"/"$file

#}

function autoupdate(){
	clear
	rm -rf $file
	echo "Downloading $file"
	wget "$link"
	if [ -f "$file" ];then
		rm -rf vpnserver
		tar xzf "$file"
		dir=$(pwd)
		echo "current dir " $dir
		cd vpnserver
		dir=$(pwd)
		echo "changed to dir " $dir
	else
		echo "Archive not found. Please rerun this script or check permission."
		break
	fi

	service stop vpnserver
	echo "updating vpn server"
	make
	cd /root/vpnserver
	chmod 600 *
	chmod 700 vpnserver
	chmod 700 vpncmd
	killall vpnserver
	cp -r * /usr/local/vpnserver/
	service start vpnserver

	clear

}

clear
checkOS
checkupdate
menu
