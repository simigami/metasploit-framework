# 
# TARGET_ID , TASK_ID, REPORT_ID,    IP, PORT, PORT PROTOCOL, CVEs, CVSS, Serverity(HIGH, Medium, Low), Vulnerability 

# TARGET_NAME=$1
# HOST=$2 

# sudo gvm-check-setup
# sudo chmod 662 /var/run/gvmd/gvmd.sock

# TARGET=$(gvm-cli --gmp-username kali --gmp-password kali socket --xml "\
# <create_target> \
# <name>$TARGET_NAME</name> \
# <hosts>$HOST</hosts> \
# <port_list id=\"33d0cd82-57c6-11e1-8ed1-406186ea4fc5\"/> \
# </create_target>")

# TARGET_ID="${TARGET#*id=\"}"
# TARGET_ID="${TARGET_ID%%\"/>}"
# echo ${TARGET_ID}

# TASK=$(gvm-cli --gmp-username kali --gmp-password kali socket --xml "<create_task> \
# <name>cli_test3</name> \
# <config id=\"daba56c8-73ec-11df-a475-002264764cea\"/> \
# <target id=\"$TARGET_ID\"/> \
# </create_task>")

# TASK_ID="${TASK#*id=\"}"
# TASK_ID="${TASK_ID%%\"/>}"
# echo ${TASK_ID}


# SCAN=$(gvm-cli --gmp-username kali --gmp-password kali socket --xml "<start_task task_id=\"$TASK_ID\"/>")

# REPORT_ID="${SCAN#*<report_id>}"
# REPORT_ID="${REPORT_ID%%</report_id>*}"
# echo $REPORT_ID

# while :
# do
# 	STATUS=$(gvm-cli --gmp-username kali --gmp-password kali socket --xml "<get_tasks task_id=\"$TASK_ID\"/>")
# 	STATUS="${STATUS#*<status>}"
# 	STATUS="${STATUS%%</status>*}"
# 	echo $STATUS
# 	if [$STATUS = "Done"]
# 	then 
# 		echo "SCANNING COMPLETE"
# 		break	
# 	fi
# 	echo "RUNNING..."
# 	sleep 3
# done

REPORT_CSV_FORMAT="c1645568-627a-11e3-a660-406186ea4fc5"
#REPORT_CSV_FORMAT="c402cc3e-b531-11e1-9163-406186ea4fc5"

REPORT_ID="7d93d1fb-0c1a-4849-9c1f-17bac5eceeeb"
CONTENT=$(gvm-cli --gmp-username kali --gmp-password kali socket --xml "<get_reports report_id=\"$REPORT_ID\" details=\"1\" ignore_pagination=\"1\" format_id=\"$REPORT_CSV_FORMAT\" />")
CONTENT="${CONTENT#*</report_format>}"
CONTENT="${CONTENT%%</report>*}"

echo $CONTENT | base64 -d > report.csv

python3 report_edit.py