#!/bin/bash
#Bash Script that pulls out commonly analyzed email header artifacts
#Author: Brian T. Carr
#Author's Personal Wesbite: briantcarr.com
#Computer Emergency Response Team Intern at the Center for Internet Security
#Any inquiries can be directed to: brian.carr@cisecurity.org
#If you improve upon this script, I encourage you to share your results. 
#42 72 69 61 6e 20 54 68 6f 6d 61 73 20 43 61 72 72 

#Input File
read -p "Enter File name...: " fname
#Regular Expressions
pattern_ipv4='[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'
pattern_email='[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}'
if [ -f $fname ]
then
	ipv4_results=$(grep -Eio --color=always "$pattern_ipv4" "$fname" | sort | uniq -c )
        email_results=$(grep -Eio --color=always "$pattern_email" "$fname" | sort | uniq -c )
        message_id=$(grep -in --color=always "Message-ID" "$fname")
        x_originating=$(grep -in --color=always "originating" "$fname")
        client_info=$(grep -in --color=always "client" "$fname")
        spf_info=$(grep -in --color=always -A 2 "spf" "$fname")
	first_hop=$(grep -in --color=always -B 3 "from: " "$fname")
        received=$(grep -in  --color=always -C  3 "received" "$fname")
        ip_addresses=$(grep -iEn --color=always "$pattern_ipv4" "$fname")

#output
	echo ___________________________________________
        echo Information regarding first hop:
        echo "$first_hop"
        echo ___________________________________________
        echo All hop information:
        echo "$received"
        echo ___________________________________________
        echo The IPv4 addresses located in context:
        echo "$ip_addresses"    
        echo ___________________________________________
        echo Here is a list of the IPv4 addresses and how many times they were located:
        echo "$ipv4_results"
        echo _____________________________________
        echo Here is a list of Email addresses and how many times they occured:
        echo "$email_results"
        echo _____________________________________
        echo The client info:
        echo "$client_info"
   	echo _____________________________________
        echo The X_originating IP address value:
        echo "$x_originating"
        echo _____________________________________
        echo The Sender Policy Framework infromation:
        echo "$spf_info"
        echo _____________________________________
        echo The Message-ID:
        echo "$message_id"
        echo =====================================

fi
		
