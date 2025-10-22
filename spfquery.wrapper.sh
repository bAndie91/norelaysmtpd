#!/bin/bash

{
max_attempts=3
attempts=0

SPF_CODE_NEUTRAL=1
SPF_CODE_PASS=2
SPF_CODE_FAIL=3
SPF_CODE_SOFTFAIL=4
SPF_CODE_NONE=5
SPF_CODE_ERROR_TEMP=6
SPF_CODE_ERROR_PERM=7
SPF_CODE_ERROR_OTHER=0
SPF_CODE_CUSTOM_NODOMAIN=8

input=`cat`

while true
do
	output=`echo "$input" | /usr/bin/spfquery "$@"`
	err=$?
	
	if [ $err = $SPF_CODE_ERROR_OTHER ] && [[ $output =~ Temporary\ DNS\ failure ]]
	then
		# spfquery not always sets the exit status as expected
		err=$SPF_CODE_ERROR_TEMP
	fi
	if [ $err = $SPF_CODE_NONE ] && [[ $output =~ Error:\ Host\ .+\ not\ found ]]
	then
		# differenciate «no such domain» and «no spf record on that domain» type of errors
		err=$SPF_CODE_CUSTOM_NODOMAIN
	fi
	
	case $err in
	($SPF_CODE_ERROR_TEMP)
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
	($SPF_CODE_ERROR_OTHER)
		# it is probably that the SPF record can not be parsed
		err=$SPF_CODE_ERROR_PERM
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
