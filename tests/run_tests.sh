#!/bin/bash

# for each pcap file in the directory, this script runs pcap2har, makes
# sure it didn't fail, then if there is an existing har file for that
# pcap, it diffs them to make sure the pcap didn't change.
# Copies pcap2har.log to a file named based on the pcap in case of failure.

for pcap in `ls *.pcap`
do
	echo $pcap
	# check normal running (with -k, that's what current test hars use)
	if ../main.py -k $pcap $pcap.new.har
	then
		if [ -a $pcap.har ]
		then
			if  diff -a -b -q  $pcap.har $pcap.new.har > /dev/null
			then
				# if diff was clean, delete file and move on
				rm $pcap.new.har
			else
				echo "  $pcap produced different har, log in $pcap.log"
				cp pcap2har.log $pcap.log
			fi
		else
			echo "  no har file to compare with for $pcap"
			continue
		fi
	else
		echo "  $pcap failed."
		cp pcap2har.log $pcap.log
	fi
	# optionally check running with --drop-bodies
	if [ -a $pcap.dropped.har ]
	then
		echo "  checking with --drop-bodies"
		if ../main.py --drop-bodies $pcap $pcap.new.dropped.har
		then
			if diff -a -b -q $pcap.dropped.har $pcap.new.dropped.har > /dev/null
			then
				# diff was clean
				rm $pcap.new.dropped.har
			else
				echo "  $pcap produced different har with --drop-bodies, see log in $pcap.dropped.log"
				cp pcap2har.log $pcap.dropped.log
			fi
		else
			echo "  $pcap failed with --drop-bodies, see log in $pcap.dropped.log"
			cp pcap2har.log $pcap.dropped.log
		fi
	fi
done

