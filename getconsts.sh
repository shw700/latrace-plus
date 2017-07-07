#!/bin/bash

# Notes
# Consider using this to sanitize all define lines, like in ptrace: sed -re 's/^#\s+define/#define/'

FILTER_ALIASES="egrep -v '^\s*#define\s+[a-zA-Z0-9_]+\s+[a-zA-Z_]+'"

SUBSTITUTIONS="AF_LOCAL AF_UNIX     SIGIOT SIGABRT"
EXCLUSIONS="IPPROTO_HOPOPTS"

function grab_between() {
	PARAM1=`echo -n $2 | sed 's/\//\\\\\//g'`
	PARAM2=`echo -n $3 | sed 's/\//\\\\\//g'`
# 	cat $1 | egrep -v '^\s+|^$|^\s*/\*' | sed "/^$PARAM1/,/^$PARAM2/"'!'"d;"
 	cat $1 | egrep -v '^\s+|^$|^\s*/\*' | sed "/$PARAM1/,/$PARAM2/"'!'"d;"
}

function grab_until() {
	grab_between $1 $2 $3 | head -n -1
}

function grab_until_not() {
	PARAM1=`echo -n $2 | sed 's/\//\\\\\//g'`
	PARAM2=`echo -n $3 | sed 's/\//\\\\\//g'`
 	cat $1 | egrep -v '^\s+|^$|^\s*/\*' | sed "/$PARAM1/,//"'!'"d;" |
		awk 'BEGIN { found=0 }{ if ($1 != "'"$PARAM2"'") { found=1 }; if (found != 1) { print} }'
}

function transform_expression() {
	new_i=`echo $1 | tr -d '()'`
	new_i_1=`echo $1 | awk -F '=' '{print $1}'`
	new_i_2=`echo $1 | awk -F '=' '{print $2}'`

	if [[ $new_i_2 =~ .*[+-|^\*].* ]]; then
		new_i=`printf '%s=%#x\n' $new_i_1 "$(($new_i_2))"`
	fi

	TRANSFORM_RESULT=$new_i
}

function make_bm_enum() {
	printf "bm_enum $1 { "
	DATA_TRANSFORMED=""
	for i in `echo "$2" | head -n -1`; do
		transform_expression $i
		DATA_TRANSFORMED="$DATA_TRANSFORMED""$TRANSFORM_RESULT"$'\n'
	done
	DATA_ONE_LINE=`echo "$DATA_TRANSFORMED" | tr '\n' ' ' | sed -n 's/ \+/ /gp' | sed 's/ /, /g'`
	printf "$DATA_ONE_LINE"
	DATA_LAST_LINE=`echo "$2"| tail -n 1`
	transform_expression $DATA_LAST_LINE
	printf "$DATA_LAST_LINE };\n\n"
}

function make_enum() {
	printf "enum $1 { "
	DATA_TRANSFORMED=""
	for i in `echo "$2" | head -n -1`; do
		transform_expression $i
		DATA_TRANSFORMED="$DATA_TRANSFORMED""$TRANSFORM_RESULT"$'\n'
	done
	DATA_ONE_LINE=`echo "$DATA_TRANSFORMED" | tr '\n' ' ' | sed -n 's/ \+/ /gp' | sed 's/ /, /g'`
	printf "$DATA_ONE_LINE"
	DATA_LAST_LINE=`echo "$2"| tail -n 1`
	transform_expression $DATA_LAST_LINE
	printf "$DATA_LAST_LINE };\n\n"
}

function run_all() {

	#grab_between /usr/include/linux/netlink.h "#define NETLINK_ROUTE" "#define NETLINK_CRYPTO"
	#grab_until_not /usr/include/linux/netlink.h "#define NETLINK_ROUTE" "#define" | eval $FILTER_ALIASES

	VARDATA=`cat /usr/include/$(uname -m)-linux-gnu/bits/socket.h | egrep "^\s*#define\s+PF_" | sed 's/PF_/AF_/' | awk '{print $2"="$3 }'`
	make_enum "socket_family" "$VARDATA"
	VARDATA=`cat /usr/include/$(uname -m)-linux-gnu/bits/socket_type.h | egrep "^\s*SOCK_.+\s=\s.+" | tr -d ',' | awk '{print $1"="$3 }'`
	make_bm_enum "socket_type" "$VARDATA"

	VARDATA=`cat /usr/include/linux/if_arp.h | egrep "^\s*#define\s+ARPHRD_" | awk '{print $2"="$3 }'`
	make_enum "arp_hardware" "$VARDATA"

	VARDATA=`cat /usr/include/openssl/ssl.h | sed -re 's/^#\s+define/#define/' | egrep "#define\s+SSL_CTRL_" | awk '{print $2"="$3 }'`
	make_enum "openssl_ctrl_cmd" "$VARDATA"
	VARDATA=`cat /usr/include/openssl/bio.h | sed -re 's/^#\s+define/#define/' | egrep "#define\s+(BIO_CTRL_|BIO_C_)" | cut -d "/" -f1 | awk '{print $2"="$3 }'`
	make_enum "bio_ctrl_cmd" "$VARDATA"
	VARDATA=`cat /usr/include/openssl/bio.h | sed -re 's/^#\s+define/#define/' | egrep "#define\s+BIO_TYPE" | cut -d "/" -f1 | awk '{print $2"="$3 }'`
	make_enum "bio_type" "$VARDATA"

	VARDATA=`cat /usr/include/asm-generic/fcntl.h | egrep "^\s*#define\s+O_.+\s+0[0-9]+.*" | egrep -v 'IOR|IOW' | awk '{print $2"="$3 }'`
	make_bm_enum "open_mode" "$VARDATA"

	return

	cat /usr/include/linux/bpf_common.h | egrep "^\s*#define\s+BPF_" | grep -v '(' | awk '{print "bpf "$2" "$3 }'

	cat /usr/include/linux/filter.h | egrep "^\s*#define\s+BPF_" | egrep -v '\(|SKF' | awk '{print "bpf "$2" "$3 }'
	cat /usr/include/linux/sched.h | egrep "^\s*#define\s+CLONE_" | egrep -v '\(|SKF' | awk '{print "clone "$2" "$3 }'
	cat /usr/include/dirent.h | egrep "\s+DT_" | grep '=' | tr -d ',' | awk '{print "readdir "$1" "$3 }'

	#missing EPOLL_CLOEXEC
	cat /usr/include/linux/eventpoll.h | egrep "^\s*#define\s+EPOLL_" | egrep -v 'EPOLL_PACKED|EPOLL_CLOEXEC' | awk '{print "epoll "$2" "$3 }'

	cat /usr/include/$(uname -m)-linux-gnu/sys/epoll.h | grep EPOLL | grep '=' | grep -v u | tr -d ',' | awk '{print "epoll "$1" "$3 }'
	cat /usr/include/linux/if_ether.h | egrep "^\s*#define\s+ETH_P_" | awk '{print "eth_prot_id "$2" "$3 }'
	cat /usr/include/asm-generic/fcntl.h | egrep "^\s*#define\s+F_" | grep -v F_LINUX_SPECIFIC_BASE |awk '{print "fcntl "$2" "$3 }'
	
	#for setsockopt: ICMPV6_FILTER

	cat /usr/include/linux/if_addr.h | egrep "^\s*#define\s+IFA_F_" | awk '{print "ifa "$2" "$3 }'
	cat /usr/include/linux/if.h | grep IFF_ | grep '= 1' | tr -d ',' | awk '{print "iff_net_device_flags "$1" "$3 }'
	cat /usr/include/linux/inotify.h | egrep "^\s*#define\s+IN_" | grep 0x | awk '{print "inotify_flags "$2" "$3 }'


	cat /usr/include/linux/futex.h | egrep "^\s*#define\s+FUTEX_.+\s+[0-9]+.*" | grep -v FUTEX_OP | grep -v 0x | awk '{print "futex "$2" "$3 }'

	#cat /usr/include/asm-generic/ioctls.h | egrep "^\s*#define\s+T" | egrep -v 'IOR|IOW' | egrep -v 'TIOCPKT_|TIOCSER_TEMT' | awk '{print "ioctl_code "$2" "$3 }'
	#cat /usr/include/asm-generic/ioctls.h | egrep "^\s*#define\s+.*\s+0x54" | awk '{print "ioctl_code "$2" "$3 }'
	cat /usr/include/asm-generic/ioctls.h | egrep "^\s*#define\s+.*\s+0x54|^\s*#define\s+TIOCPKT.+" | awk '{print "ioctl_code "$2" "$3 }'
	cat /usr/include/asm-generic/termios.h | egrep "^\s*#define\s+TIOCM_.+\s+[0-9]+.*" | egrep -v 'IOR|IOW' | awk '{print "ioctl_termios "$2" "$3 }'

	grab_between /usr/include/linux/in6.h "IPV6_ADDRFORM" "cantfindthisrandomgarbagestring" | egrep "^\s*#define\s+IPV6_" | awk '{print "ipv6_socket_options "$2" "$3 }'

	cat /usr/include/netinet/in.h | egrep "\s*IPPROTO_.*\s+=\s+" | tr -d ',' | awk '{print "ip_proto "$1" "$3 }'	

	cat /usr/include/$(uname -m)-linux-gnu/bits/mman*.h | sed -re 's/^#\s+define/#define/' | egrep "^\s*#\s*define\s+MAP_[_a-zA-Z0-9]+\s+.*[0-9]+.*" | awk '{print "mmap_flags "$2" "$3 }'
	cat /usr/include/asm-generic/mman-common.h | sed -re 's/^#\s+define/#define/' | egrep "^\s*#\s*define\s+MADV_[_a-zA-Z0-9]+\s+.*[0-9]+.*" | awk '{print "madvise_advice "$2" "$3 }'
	
	grab_until_not /usr/include/linux/netlink.h "^#define NETLINK_ROUTE" "#define" | egrep "^\s*#define\s+NETLINK_" | awk '{print "netlink_type "$2" "$3 }'
	cat /usr/include/linux/netlink.h | egrep "^\s*#define\s+NLM_.+\s+.*[0-9]+" | awk '{print "netlink_flags "$2" "$3 }'

	cat /usr/include/asm-generic/mman-common.h | egrep "^\s*#define\s+PROT_" | awk '{print "mmap_prot "$2" "$3 }'

	grab_until /usr/include/linux/fs.h "MS_RDONLY" "MS_RMT_MASK" | egrep "^\s*#define\s+MS_" | awk '{print "mount_flags "$2" "$3 }'

	cat /usr/include/$(uname -m)-linux-gnu/bits/socket.h | egrep "^\s*MSG_[_a-zA-Z0-9]+\s+=\s+.*[0-9]+.*" | tr -d ',' | awk '{print "msg_io_flags "$1" "$3 }'

	cat /usr/include/linux/prctl.h | egrep "^\s*#define\s+PR_" | awk '{print "prctl_opts "$2" "$3 }'
	cat /usr/include/asm/ptrace-abi.h | sed -re 's/^#\s+define/#define/' | egrep "^\s*#\s*define\s+PTRACE_.+[0-9]+" | awk '{print "ptrace "$2" "$3 }'
	cat /usr/include/$(uname -m)-linux-gnu/sys/ptrace.h | egrep "^\s*PTRACE_.+[0-9]+" | grep -v '(' | tr -d ',' | awk '{print "ptrace "$1" "$3}'

	cat /usr/include/asm-generic/resource.h | sed -re 's/^#\s+define/#define/' | egrep "^\s*#define\s+RLIMIT" | awk '{print "rlimit "$2" "$3 }'

	cat /usr/include/linux/rtnetlink.h | egrep "\s+RTM_" | grep '=' | tr -d ',' | awk '{print "rtnetlink_msg_type "$1" "$3 }'
	cat /usr/include/linux/sockios.h | egrep "^\s*#define\s+SIOC" | awk '{print "ioctl_socket "$2" "$3 }'

	cat /usr/include/asm-generic/socket.h | egrep "^\s*#define\s+SO_.+\s+[0-9]+" | awk '{print "setsockopt_optname "$2" "$3 }'


	cat /usr/include/asm/unistd_64.h | egrep "^\s*#define\s+__NR_" | sed 's/__NR_//' | awk '{print "syscall_name "$2" "$3 }'
	cat /usr/include/asm-generic/errno-base.h /usr/include/asm-generic/errno.h | egrep "^\s*#define\s+E" | awk '{print "errno "$2" "$3 }'
	cat /usr/include/asm/signal.h | egrep "^\s*#define\s+SIG" | awk '{print "signal "$2" "$3 }'

	egrep -r "^\s*#\s*define\s+SOL_[A-Z]+\s+[0-9]" /usr/include/ | awk -F '#' '{print $2}' | awk '{print "sol_level", $2, $3}' | sort -u -n -k 3

	grab_between /usr/include/linux/tcp.h "TCP_NODELAY" "TCP_REPAIR_WINDOW" | egrep "^\s*#define\s+TCP_" | awk '{print "sockopt_tcp "$2" "$3 }'
}


# Create the substitutions string
SEDSTRING=''
COUNTER=0
FIRST=1

for i in $SUBSTITUTIONS; do
	COUNTER=$(expr $COUNTER + 1)

	if [ $(($COUNTER % 2)) != 0 ]; then
		SEDSTRING=$SEDSTRING"s/$i/"
	else
		SEDSTRING=$SEDSTRING"$i/g;"
	fi

done


GREPSTRING=''
FIRST=1

for i in $EXCLUSIONS; do

	if [ $FIRST -eq 1 ]; then
		FIRST=0
	else
		GREPSTRING="$GREPSTRING""|"
	fi

	GREPSTRING="$GREPSTRING""$i"
done

# Remove any aliases, and then perform any necessary substitutions
run_all
#run_all| awk '$3 ~ /^[^_a-zA-Z]+/' | sed "$SEDSTRING" | egrep -v "$GREPSTRING"
