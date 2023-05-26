EXPLOIT=$1
RESULT=$(msfconsole -qx "use $EXPLOIT;show payloads; exit -y") 
#echo "$RESULT" | grep "payload" | awk '{ print ( $1 ", " $2 "," "\"" $5$6$7$8$9$10$11$12 "\"") }'
RESULT=$(echo "$RESULT" | grep "payload" | awk '{ print ( $1 ", " $2 "," "\"" $5$6$7$8$9$10$11$12$13 "\"") }')
echo "#, name, Description\n$RESULT" > output_payload.csv
