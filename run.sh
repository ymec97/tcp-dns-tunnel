#!/usr/bin/env bash


if [[ $UID -ne 0 ]]
then
	echo "Please run script as sudo"
	exit 1
fi


function usage {
	echo "./run.sh [-h]|-m <MODE>
	-h|--help 	Print this usage message
	-m|--mode   MODE - server / client"
}


SERVER_SCRIPT_NAME=server.py
CLIENT_SCRIPT_NAME=client.py
MIN_ARG_COUNT=1
DID_SETUP=0
EXECUTION_RES=0
TUN_IP="10.0.0.1"
ACTIVE_IFACE=$(ip route get 8.8.8.8 | awk '{print $5}')
ACTIVE_IP_ADDR=$(ip addr show | grep -w $ACTIVE_IFACE |  awk '/inet / {print $2}' | grep -v '127.0.0.1' | cut -f1 -d'/')
SERVER_IP=""


if [[ $# -lt $MIN_ARG_COUNT ]]
then
	printf "Wrong number of arguments passed. Expected: %d, got %d\n" $# $MIN_ARG_COUNT
	usage
	exit 1
fi

while [[ $# -gt 0 ]]; do
  case $1 in
    -h|--help) 
		usage
		exit 0;;
    -m|--mode) 
		MODE="$2"
		if [[ "$MODE" != "server" ]] && [[ "$MODE" != "client" ]]
		then
			printf "invalid mode received. expected server/client, got: %s\n" "'$MODE'"
			exit 1
		fi
		shift
		break;;
    *) 
		echo "Unknown parameter $1"
		exit 1
  esac
  shift
done

function setup_tunif {
  modprobe tun
  ip tuntap add mode tun dev tun0 || cleanup
  ip addr add "$TUN_IP"/24 dev tun0 || cleanup
  ip link set dev tun0 up || cleanup
  ip link set mtu 1500 dev tun0 || cleanup
}

function cleanup_tunif {
  ip tuntap del mode tun dev tun0
}

function cleanup_client {
	echo "Cleaning up tunnel configuration as client"
	set -x
	ip rule delete fwmark 2 table 3
	iptables -t mangle -D OUTPUT -p tcp -s $ACTIVE_IP_ADDR -j MARK --set-mark 2
	iptables -t nat -D PREROUTING -p udp -m "udp" --dport 53 -j DNAT --to-destination 127.0.0.1:53
	cleanup_tunif
	echo "Client configuration cleaned"
}

function setup_client {
	echo "Applying tunnel configuration as client"
	set -x
	setup_tunif
	# Packets marked with 2 are routed by the rules described in table 3
	ip rule add fwmark 2 table 3 || cleanup
	DID_SETUP=1
	# Mark tcp packets outgoing from the local machine with “2” (Using OUTPUT because this is the chain that packets go through when leaving the system)
	iptables -t mangle -A OUTPUT -p tcp -s $ACTIVE_IP_ADDR -j MARK --set-mark 2 || cleanup
  iptables -t nat -A PREROUTING -p udp -m "udp" --dport 53 -j DNAT --to-destination 127.0.0.1:53
	# Add tun0 ip as the default gw for table 3, so all tcp packets routed with table 3 will be routed to the tun interface
	ip route add default via "$TUN_IP" table 3 || cleanup
	set +x
	echo "Client configuration applied"
}

function cleanup_server {
	echo "Cleaning up tunnel configuration as server"
	set -x
	iptables -t nat -D PREROUTING -p udp -m "udp" --dport 53 -j DNAT --to-destination 127.0.0.1:53
	iptables -D OUTPUT -p tcp -m tcp --tcp-flags RST RST -j DROP
#	ip rule delete fwmark 2 table 3
#	iptables -t mangle -D PREROUTING -p udp -m "udp" --dport 53 -j MARK --set-mark 2
#	cleanup_tunif
	set +x
	echo "Server configuration cleaned"
}

function setup_server {
	echo "Applying tunnel configuration as server"
	set -x
#	setup_tunif
  iptables -t nat -A PREROUTING -p udp -m "udp" --dport 53 -j DNAT --to-destination 127.0.0.1:53
	iptables -A OUTPUT -p tcp -m tcp --tcp-flags RST RST -j DROP
	DID_SETUP=1
	# Packets marked with 2 are routed by the rules described in table 3
#	ip rule add fwmark 2 table 3 || cleanup
#	iptables -t mangle -A PREROUTING -p udp -m "udp" --dport 53 -j MARK --set-mark 2 || cleanup
#	ip route add default via "$TUN_IP" table 3 || cleanup
	set +x
	echo "Server configuration applied"
}

function setup {
	if [[ "$MODE" == "server" ]]
	then
		setup_server || exit 1
	else
		setup_client || exit 1
	fi
}

function cleanup {
	set +x
	if [[ $DID_SETUP -eq 0 ]]
	then
		echo "No clean up needed - exiting"
		exit $EXECUTION_RES
	fi

	if [[ "$MODE" == "server" ]]
	then
		cleanup_server || exit 1
	else
		cleanup_client || exit 1
	fi

	exit $EXECUTION_RES
}

function is_valid_ip {
  ip_address=$1

  if ! [[ $ip_address =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]];
  then
    return 0
  fi
  octets=($(echo "$ip_address" | tr '.' ' '))
  for octet in "${octets[@]}"
   do
      if [[ ! $octet =~ ^[0-9]+$ ]] || (( octet < 0 || octet > 255 )); then
        return 0
      fi
  done
  return 1
}

function init_server_ip {
	while true; 
	do
	    read -p "Enter the server's IP address: " SERVER_IP
      is_valid_ip "$SERVER_IP"
	    if [ $? -eq 0 ]
	    then
	      echo "'$SERVER_IP' is not a valid IP address, please try again"
	      continue
      fi
      echo "Checking connectivity with server at: $SERVER_IP"
      ping -c1 -W 1 "$SERVER_IP" &> /dev/null
    	if [ $? -eq 0 ]
    	then
          echo "Server is alive"
          break
      else
          echo "Failed contacting server. please make sure you've given the right IP. If the problem persists make sure the server is alive"
      fi
  done
}
trap 'cleanup' SIGHUP SIGINT SIGTERM

if [[ "$MODE" == "server" ]]
then
  EXTRA_SCRIPT_ARGS=""
	if [[ ! -f  "$SERVER_SCRIPT_NAME" ]]
	then
		echo "
	File $SERVER_SCRIPT_NAME wasn't found in current directory
	Please cd to the programs directory\
	"
		exit 1
	fi
	 
	SCRIPT_TO_RUN=$SERVER_SCRIPT_NAME
else
	init_server_ip
	EXTRA_SCRIPT_ARGS="$SERVER_IP"
	if [[ ! -f  "$CLIENT_SCRIPT_NAME" ]]
	then
		echo "
	File $CLIENT_SCRIPT_NAME wasn't found in current directory
	Please cd to the programs directory\
	"
		exit 1
	fi
	SCRIPT_TO_RUN=$CLIENT_SCRIPT_NAME
fi


setup || exit 1
RUN_FROM_SCRIPT=true ./$SCRIPT_TO_RUN $EXTRA_SCRIPT_ARGS || EXECUTION_RES=$?
if [[ $EXECUTION_RES -ne 0 ]]
then
	echo "Error running script"
fi
cleanup || exit 1


exit 0
