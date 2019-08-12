#!/bin/bash
#Bash Script that pulls out commonly analyzed email header artifacts
#Author: Brian T. Carr
#Author's Personal Wesbite: briantcarr.com
#Computer Emergency Response Team Intern at the Center for Internet Security
#Any inquiries can be directed to: brian.carr@cisecurity.org
#If you improve upon this script, I encourage you to share your results. 
#62 72 69 61 6e 74 63 61 72 72 2e 63 6f 6d 0a 

#Input File
read -p "Enter File name...: " fname
#Regular Expressions
pattern_ipv4='[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'
pattern_ipv6='(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))'
pattern_email='[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}'
if [ -f $fname ]
then
	ipv4_results=$(grep -Eio --color=always "$pattern_ipv4" "$fname" | sort | uniq -c )
        email_results=$(grep -Eio --color=always "$pattern_email" "$fname" | sort | uniq -c )
        message_id=$(grep -in --color=always -A 1 "Message-ID" "$fname")
        x_originating=$(grep -in --color=always "originating" "$fname")
        client_info=$(grep -in --color=always -A 2 "client" "$fname")
        spf_info=$(grep -n --color=always -A 1 "spf" "$fname")
	first_hop=$(grep -in --color=always -B 3 "from: " "$fname")
        received=$(grep -in  --color=always -C  3 "received" "$fname")
        ip_addresses=$(grep -iEn --color=always "$pattern_ipv4" "$fname")
	ipv6_address=$(grep -iEn --color=always "$pattern_ipv6" "$fname")
	ipv6_list=$(grep -iEo --color=always "$pattern_ipv6" "$fname" | sort | uniq -c)

#output
	if [ -z "$first_hop" ]
	then
		echo ++++++++++++++++++++++++++++++++++++++++++++++

	else
		echo ______________________________________________
        	echo Information regarding first hop:
        	echo "$first_hop"
        	echo ______________________________________________
	fi
	if [ -z "$received" ]
	then
		echo ++++++++++++++++++++++++++++++++++++++++++++++
	else
		echo All hop information:
      		echo "$received"
        	echo ______________________________________________
	fi
	if [ -z "$ip_addresses" ]
	then
		echo ++++++++++++++++++++++++++++++++++++++++++++++
	else
		echo The IPv4 addresses located in context:
        	echo "$ip_addresses"    
        	echo ______________________________________________
	fi
	if [ -z "$ipv4_results" ]
	then
		echo ++++++++++++++++++++++++++++++++++++++++++++++

	else
		echo Here is a list of the IPv4 addresses and how many times they were located:
        	echo "$ipv4_results"
        	echo ______________________________________________
	fi
	if [ -z "$ipv6_address" ]
	then
		echo +++++++++++++++++++++++++++++++++++++++++++++++
	else
		echo The IPv6 addresses in context:
        	echo "$ipv6_address"
		echo ______________________________________________
	fi
	if [ -z "$ipv6_list" ]
	then 
		echo ++++++++++++++++++++++++++++++++++++++++++++++

	else	
		echo A list of IPv6 addresses and how many times they were located:
		echo "$ipv6_list"
		echo ______________________________________________
	fi
	if [ -z "$email_results" ]
	then 
		echo ++++++++++++++++++++++++++++++++++++++++++++++

	else
		echo Here is a list of Email addresses and how many times they occured:
        	echo "$email_results"
        	echo ______________________________________________
	fi
	if [ -z "$client_info" ]
	then
		echo ++++++++++++++++++++++++++++++++++++++++++++++

	else
		echo The client info:
        	echo "$client_info"
   		echo ______________________________________________
	fi
	if [ -z "$x_originating" ]
	then
		echo ++++++++++++++++++++++++++++++++++++++++++++++

	else	
		echo The X_originating IP address value:
        	echo "$x_originating"
        	echo ______________________________________________
	fi
	if [ -z "$spf_info" ]
	then
		echo ++++++++++++++++++++++++++++++++++++++++++++++

	else	
		echo The Sender Policy Framework infromation:
        	echo "$spf_info"
        	echo ______________________________________________
	fi
	if [ -z "$message_id" ]
	then
		echo ++++++++++++++++++++++++++++++++++++++++++++++

	else 
		echo The Message-ID:
        	echo "$message_id"
        	echo ==============================================
	fi
fi
		
