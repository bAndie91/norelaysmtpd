#!/bin/bash

{
max_attempts=3
attempts=0

input=`cat`

while true
do
	output=`echo "$input" | /usr/bin/spfquery "$@"`
	err=$?
	
	if [ $err = 0 ] && [[ $output =~ Temporary\ DNS\ failure ]]
	then
		# spfquery not always sets the exit status as expected
		err=6
	fi
	
	case $err in
	(6)
		# temp error.
		# probably DNS is slow right now.
		# retry.
		attempts=$[attempts+1]
		if [ $attempts -ge $max_attempts ]
		then
			break
		fi
		echo "spfquery attempt $attempts:" >&2
		echo "$output" | sed -e 's/^/  /' >&2
		echo "spfquery exit code $err detected. retrying..." >&2
		;;
	(0)
		# it is probably that the SPF record can not be parsed
		err=7
		break
		;;
	(*)
		break
		;;
	esac
done

echo "$output"
exit $err
}
