#!/bin/bash
INPUT=/tmp/menu.sh.$$
NETINPUT=/tmp/netinput.sh.$$
DISKINPUT=/tmp/diskinput.sh.$$
CMDINPUT=/tmp/cmdinput.sh.$$
HWINPUT=/tmp/hardwareinput.sh.$$
SERVICEINPUT=/tmp/serviceinput.sh.$$
INSTALLINPUT=/tmp/installinput.sh.$$
BACKUPINPUT=/tmp/backinput.sh.$$
CURRRENT_PATH=$(pwd)
source_dir='/usr/local/tools'
title='System Operations tools-v.2'
backtitle='System Operations Tools Created by Welliam.Cao 2014/05/14 Email: 303350019@qq.com'
REMOTE_CMD='./script/auto_remote_commands.sh'
if [[ -d /usr/local/mysql/bin/  ]]
   then
     MYSQL_PATH='/usr/local/mysql/bin'
   else
     MYSQL_PATH='/usr/bin/'
fi
################################ ---------------------- netowrk begin ---------------------------------- ##########################
######################### display network ##########################
dis_network(){
dialog --backtitle "${backtitle}"  --title "${title}" --menu "Make your decisions" 12 55 5 \
 1 "configure your IP address." \
 2 "add gateway." \
 3 "config DNS nameserver." \
 4 "test your network." \
 5 "check the network transmission rate." 2>"${NETINPUT}"
dis_network_c=$(<"${NETINPUT}")
case ${dis_network_c} in
    1)  dis_confirm_network_conf;;
    2)  dis_network_gw;;
    3)  dis_network_dns;;
    4)  dis_test_network_conf;;
    5)  dis_check_network_rate;;
esac
}
dis_confirm_network_conf(){
dialog --backtitle "${backtitle}"  --title "${title}" --menu "Make your decisions" 12 55 5  $(ifconfig |awk 'BEGIN{ORS='\n'}/HWaddr/{print$1" netcard_"$1"\t"}')  2>"${NETINPUT}"
dis_card_c=($(<"${NETINPUT}"))
if [[ -n ${dis_card_c} ]]
    then
      confirm_network_conf
    else
      dis_network
fi
}

confirm_network_conf(){
dialog  --backtitle "${backtitle}" --title "${title}" --inputbox  "Please input  ipaddress:" 12 50  2>"${NETINPUT}"
dis_network_c=($(<"${NETINPUT}"))
ifconfig ${dis_network_c}
dis_network
#echo -e "route add default gw ${dis_network_c[1]}"
#echo -e "nameserver  ${dis_network_c[2]}  >>  /etc/resolv.conf"
}
dis_network_gw(){
dialog  --backtitle "${backtitle}" --title "${title}" --inputbox  "Please input gateway:" 12 50  2>"${NETINPUT}"
dis_network_c=($(<"${NETINPUT}"))
route add default gw ${dis_network_c}
dis_network
}
dis_network_dns(){
dialog  --backtitle "${backtitle}" --title "${title}" --inputbox  "Please input DNS nameserver:" 12 50  2>"${NETINPUT}"
dis_network_c=($(<"${NETINPUT}"))
echo "nameserver  ${dis_network_c}"  >>  /etc/resolv.conf
dis_network
}
######################### for display test configure ####################
dis_test_network_conf(){
dialog  --backtitle "${backtitle}" --title "${title}" --form "Please input the IPADDRESS OR DOMIANNAME:" 12 50 3  \
"Frist:" 1  1 "" 1  15  20  0  \
"Second:" 2  1 "" 2  15  20  0  \
"Third:" 3 1 "" 3 15  20  0 2>"${NETINPUT}"
dis_network_c=($(<"${NETINPUT}"))
for i in ${dis_network_c[@]}
    do
        ping ${i} -f -c 4 >/dev/null 2>&1
        if [[ $? -eq 0 ]]
            then
                dialog --clear --backtitle "${backtitle}" --title "connect to  ${i}" --msgbox "connect ${i} successful." 10 40
        elif [[ $? -gt 0 ]]
            then
                dialog --clear --backtitle "${backtitle}" --title "connect to  ${i}" --msgbox "error ${i} is unreachable." 10 40
        fi
done
dis_network
}
####################### for display test network spped #################
dis_check_network_rate(){
card=$(ifconfig |awk 'NR==1{print$1}')
speed=$(ethtool ${card}|grep -oP "(?<=Speed: ).*")
dialog --clear --backtitle "${backtitle}" --title "Network card ${card}" --msgbox "your network card ${card} is ${speed} transmission rate." 10 40
dis_network
}
########################### --------------------------  network end -------------------------------- ####################

########################### -------------------------- disk begin ---------------------------- ####################
dis_disk(){
dialog --backtitle "${backtitle}"  --title "${title}" --menu "Make your decisions" 12 55 2 \
 1 "TEST disk read speed." \
 2 "TEST disk write speed." 2>"${DISKINPUT}"
dis_disk_c=$(<"${DISKINPUT}")
case $dis_disk_c in
    1)  disk_read;;
    2)  disk_write;;
    *) echo "[ESC] key pressed";;
esac
}
########################### disk_read ###############################
disk_read(){
DISK=$(fdisk -l|awk -F'[ :]+' '/Disk/&&NR==2{print$2}')
dialog  --backtitle "${backtitle}" --title "${title}" --msgbox "Disk tool will be begin initialization." 10 50
r_speed=$(hdparm -Tt ${DISK}|awk '/buffered/{print"Read Speed: "$11$12}')
for i in {10,20,30,40,50,60,70,80,90,100}
    do echo $i
    sleep 2 
done | dialog --clear --backtitle "${backtitle}" --title " Waiting for Results of Test " --gauge "Disk read test completion" 8 50
dialog --clear --backtitle "${backtitle}" --title "Disk ${DISK}" --msgbox " ${DISK} ${r_speed}" 10 50
dis_disk
}
########################## disk_write ###############################
disk_write(){
dialog  --backtitle "${backtitle}" --title "${title}" --msgbox "This function is designed\n\
you can use command like:\n\
'dd if=/dev/zero of=/tmp/output.img bs=8k count=256k;rm -rf /tmp/output.img'\n\
GoodLuck for you." 10 50
dis_disk
}
########################### -------------------------- disk end ------------------------------ ####################


########################## ------------------------- remote begin ------------------------------ ######################
dis_cmd(){
dialog  --backtitle "${backtitle}" --title "${title}" --form "Please fill in accordance with the following information" 12 50 4  \
"IPADDRESS:" 1  1 "" 1  15  20  0  \
"USER:" 2  1 "" 2  15  20  0  \
"PORT:" 3 1 "" 3 15  20  0 \
"SHELL:" 4 1 "" 4 15  20  0 2>"${CMDINPUT}"
INFO=($(<"${CMDINPUT}"))
remote_cmd
}
##################################### remote cmd ###########################
remote_cmd(){
dialog --backtitle "${backtitle}"  --title  "Input Password"  --insecure  --passwordbox  "Please input password for root:"  10 30 2>"${CMDINPUT}"
PASSWD=$(<"${CMDINPUT}")
${REMOTE_CMD}  ${INFO[0]} ${INFO[1]} ${PASSWD} ${INFO[2]} ${INFO[3]}
}
########################## ------------------------- remote end ------------------------------ ######################
################################ host info begin ##################################
dis_info(){
echo -e "================ Host soft infomation ================ \
\nHost_name: $(hostname)\nSoft System: $(cat /etc/issue|sed -ne '1p') \
\nLinux kernel versions: $(uname -na|awk '{print$3}')\
\nUptime:$(uptime |awk -F',' '{print$1}')" >${HWINPUT}
echo -e "\n" >> ${HWINPUT}
ifconfig |awk  'BEGIN{RS="";print"================= Network infomation ================="}/HWaddr/&&$7~/addr/{gsub(/:/,"-",$5);gsub(/inet/,"\tIP",$6);gsub(/:/,": ",$7);print$1"\t"$4":",$5"\n"$6,$7}' >>${HWINPUT}
echo -e "\n" >> ${HWINPUT}
awk -F':' 'BEGIN{print"================= Accout infomation =================\nThe accout who can login in the system:"}!/(nologin|shutdown|sync|halt)/{print$1"\t"$6}' /etc/passwd >> ${HWINPUT}
who|awk -F'[)( ]+' 'BEGIN{print"current login user:"}/pts/{print$1"\t"$5}' >> ${HWINPUT}
echo -e "\n" >> ${HWINPUT}
echo -e "Login failed IPAddress." >> ${HWINPUT}
ipinfo=($(awk 'BEGIN{ORS=" "}/Failed password/{a[$11]++}END{for(x in a)if(a[x]>3)print x}' /var/log/secure))
for ip in ${ipinfo[*]}
   do
    if [[ ${ip} != 192.168.*.*  ]] && [[ ${ip} != 172.16.*.*  ]] && [[ ${ip} != 10.*.*.*  ]]
       then
          ipzone=$(curl  -s --user-agent "[Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; TencentTraveler 4.0)]"  http://ip.qq.com/cgi-bin/searchip?searchip1=${ip}|grep '<p>'|iconv -f gb2312 -t utf-8|grep -oP '(?<=n>).*(?=</sp)'|sed 's/&nbsp;/ /g')
          echo "${ip}:  ${ipzone}"  >> ${HWINPUT}
       else
          echo "Local area network: ${ip}" >> ${HWINPUT}
    fi
done
echo -e "\n" >> ${HWINPUT}
echo "================= Hardware infomation =================" >> ${HWINPUT}
echo "-------------------- CPU INFOMATION -------------------" >> ${HWINPUT}
awk -F':' '/model name/&&!a[$0]++{print"CPU model:"$2}' /proc/cpuinfo >> ${HWINPUT}
echo -e "CPU physical number: $(grep 'physical id' /proc/cpuinfo|uniq |wc -l)" >> ${HWINPUT}
echo -e "CPU core number: $(grep 'core id' /proc/cpuinfo | sort -u | wc -l)" >> ${HWINPUT}
echo -e "CPU thread number: $(grep 'processor' /proc/cpuinfo | sort -u | wc -l)" >> ${HWINPUT}
echo -e "Whether to support virtualization ?" >> ${HWINPUT}
if [[ $(grep -E "(vmx|svm)" /proc/cpuinfo |wc -l) -gt 0 ]]
    then
         echo "Virtualization support." >> ${HWINPUT}
    else
        echo "Don't support Virtualization." >> ${HWINPUT}
fi
echo -e "\n" >> ${HWINPUT}
echo "-------------------- MEM INFOMATION -------------------" >> ${HWINPUT}
dmidecode |grep -A5  "Memory Device$" |awk  '$0~/Size: [0-9]+/{a[$2]++;sum+=$2}END{for(x in a)print a[x]" pieces of",x" MB memory";print "Total of "sum" MB"}' >> ${HWINPUT}
free -m|awk '/Mem/{print$4"MB can be use."}' >> ${HWINPUT}
echo -e "\n" >> ${HWINPUT}
echo "------------------- DISK INFOMATION - -----------------" >> ${HWINPUT}
echo "Disk list:" >> ${HWINPUT}
fdisk -l|awk -F',' '/Disk \/dev/{print$1}' >> ${HWINPUT}
echo "Partition of Disk:" >> ${HWINPUT}
df -lh >> ${HWINPUT}
echo -e "\n" >> ${HWINPUT}
echo "------------------- MACHINE INFOMATION -----------------" >> ${HWINPUT}
dmidecode | grep "Product Name" |awk -F':' 'NR==1{print"Machine model: "$2}' >> ${HWINPUT}
dmidecode | grep "Product Name" |awk -F':' 'NR==2{print"Machine serial number: "$2}' >> ${HWINPUT}
echo -e "\n" >> ${HWINPUT}
dialog  --backtitle "${backtitle}"  --title "A REPORT OF HOST"  --textbox  ${HWINPUT} 20 60
>${HWINPUT}
}
################################ host info end ####################################

######################################----------------- confifure services -----------------------########################################
conf_service(){
dialog --backtitle "${backtitle}"  --title "${title}" --menu "Make your decisions" 12 55 5 \
 1 "config apache." \
 2 "config nginx." \
 3 "config mysql." \
 4 "config php." \
 5 "config iptables." 2>"${SERVICEINPUT}"
local dis_ser_s_c=$(<"${SERVICEINPUT}")
case ${dis_ser_s_c} in
    1)  conf_service_apache;;
    2)  conf_service_nginx;;
    3)  conf_service_mysql;;
    4)  conf_service_php;;
    5)  conf_fw;;
esac
}
conf_service_apache(){
dialog --backtitle "${backtitle}"  --title "${title}" --menu "Make your decisions" 12 55 3 \
 1 "modify apache ServerName." \
 2 "modify apache Ports." \
 3 "modify apache Docment Path." 2>"${SERVICEINPUT}"
local dis_conf_ser=$(<"${SERVICEINPUT}")
case ${dis_conf_ser} in
    1)
      dialog --backtitle "${backtitle}"  --title "${title}" --inputbox "like www.baidu.com or 192.168.10.88" 10 30  2>"${SERVICEINPUT}"
      domain_name=$(<"${SERVICEINPUT}")
      if [[ $(echo ${domain_name}|grep -Eo "[^a-z0-9A-Z.]"|wc -l) -gt 0 ]]
          then
              dialog --clear --backtitle "${backtitle}" --title "${title}" --msgbox "DOMAIN/IPaddress format is error." 10 40
              unset -v domian_name
              conf_service_apache
          else
             domain_name=$(<"${SERVICEINPUT}")
             sed -i 's/^#ServerName/ServerName/' /etc/httpd/conf/httpd.conf
             sed -i 's/^ServerName.*/ServerName '"${domain_name}:80"'/' /etc/httpd/conf/httpd.conf
             dis_success
      fi
    ;;
    2)
      dialog --backtitle "${backtitle}"  --title "${title}" --inputbox "like 80 or 8080" 10 30  2>"${SERVICEINPUT}"
      apache_port=$(<"${SERVICEINPUT}")
      if [[ $(echo ${apache_port}|grep -oE "[^0-9]"|wc -l)  -gt 0  ]] && [[ $(echo ${#apache_port}) -gt 4 ]]
          then
              dialog --clear --backtitle "${backtitle}" --title "${title}" --msgbox "Error format,port range must be 1 < ports < 10000" 10 40
              unset -v apache_port
               conf_service_apache
     else
         apache_port=$(<"${SERVICEINPUT}")
         sed -i '/^ServerName/s/:[0-9]\{1,4\}/:'"${apache_port}"'/g' /etc/httpd/conf/httpd.conf
         dis_success
     fi
    ;;
    3)
       dialog --backtitle "${backtitle}"  --title "${title}" --inputbox "like \/var\/www\/html" 10 30  2>"${SERVICEINPUT}"
       local doc_path=$(<"${SERVICEINPUT}")
       if [[ $(echo ${doc_path}|grep -oE '(&|*|\(|\)|\^|\$|%|@|\`|\!)'|wc -l) -gt 0 ]]
          then
            dialog --clear --backtitle "${backtitle}" --title "${title}" --msgbox "there are abnormal character by you input" 10 40
            conf_service_apache
          else
            sed -i '/^DocumentRoot/s/\".*\"/\"'"${doc_path}"'\"/g' /etc/httpd/conf/httpd.conf
       fi
    ;;
esac
}
conf_service_mysql(){
check_mysql_service(){
dialog  --backtitle "${backtitle}" --title "${title}" --no-shadow --yesno "Mysql is not startup,do you want start ? " 8 50
local response=$?
case $response in
    0)
     service mysqld start >/dev/null 2>&1
     dis_success
    ;;
    1)  conf_service_mysql;;
esac
}
dialog --backtitle "${backtitle}"  --title "${title}" --menu "Make your decisions" 12 55 3 \
 1 "modify mysql root password." \
 2 "create database."  \
 3 "drop database" 2>"${SERVICEINPUT}"
local dis_conf_ser=$(<"${SERVICEINPUT}")
case ${dis_conf_ser} in
  1)
    if [[ $(ps axu|grep mysqld|wc -l) -lt 2 ]]
        then
          check_mysql_service
        else
           dialog  --backtitle "${backtitle}" --title "${title}" --form "Please input password:" 12 50 3 "Old password:" 1  1 "" 1  15  20  0  "New password:" 2  1 "" 2  15  20  0  2>"${SERVICEINPUT}"
           local dis_passwd_c=($(<"${SERVICEINPUT}"))
           if [[ $(echo ${#dis_passwd_c[@]}) -eq 2 ]]
            then
             local e_info='Old password error or abnormal character!'
             ${MYSQL_PATH}/mysqladmin  -uroot -p${dis_passwd_c[0]} password ${dis_passwd_c[1]} > /dev/null 2>&1
             dis_success
       fi
    fi
   #conf_service
  ;;
  2)
    dialog --backtitle "${backtitle}"  --title "${title}" --inputbox "If you have multiple databases,input like: dbone,dbtwo,dbthree " 10 50  2>"${SERVICEINPUT}"
    local dis_dbname_c=($(echo $(<"${SERVICEINPUT}")|sed 's/,/ /g'))
    dialog --backtitle "${backtitle}"  --title "${title}" --insecure --passwordbox  "Please input root passwd" 10 40  2>"${SERVICEINPUT}"
    local dis_dbname_pwd=($(<"${SERVICEINPUT}"))
    for dbn in ${dis_dbname_c[@]}
	do
           local s_info="Congratulations create database ${dbn} "
           local e_info="Check your password or maybe database ${dbn} is exsit"
           ${MYSQL_PATH}/mysql -uroot -p${dis_dbname_pwd} -e " CREATE DATABASE ${dbn}" >/dev/null 2>&1
           dis_success
    done
  ;;
  3)
    dialog --backtitle "${backtitle}"  --title "${title}" --insecure --passwordbox  "Please input root passwd" 10 40  2>"${SERVICEINPUT}"
    local dis_dbname_pwd=$(<"${SERVICEINPUT}")
    ${MYSQL_PATH}/mysql -uroot -p${dis_dbname_pwd}  -e "show databases" > ${SERVICEINPUT}
    dialog --backtitle "${backtitle}" --title "${title}"  --checklist "Which do you want drop,make your choice?" 20 50 10 $(awk 'BEGIN{ORS='\n'}NR>2{print $0,"Database_"$0,NR-2" "}' ${SERVICEINPUT} ) 2>${SERVICEINPUT}
    local dbn_rs=($(echo $(<"${SERVICEINPUT}")| sed -ne 's/\"//gp' ))
    for rs in ${dbn_rs[@]}
      do
        local s_info="Congratulations drop database ${rs} "
        local e_info="Check your password or maybe database ${rs} is not exsit "
        ${MYSQL_PATH}/mysql -uroot -p${dis_dbname_pwd}  -e "DROP DATABASE  ${rs} " >/dev/null 2>&1
        dis_success
    done
  ;;
esac
}
conf_service_nginx(){
source ./bin/vir_nginx
dialog --backtitle "${backtitle}"  --title "${title}" --menu "Make your decisions" 12 55 3 \
 1 "Configure the virtual host." \
 2 "OPEN SOON."  \
 3 "OPEN SOON" 2>"${SERVICEINPUT}"
local dis_conf_ser=$(<"${SERVICEINPUT}")
case ${dis_conf_ser} in
    1)
       dialog  --backtitle "${backtitle}" --title "${title}" --form "Pls input Virtual host name and docment path." 12 50 3  \
"ServerName:" 1  1 "" 1  15  20  0  \
"ROOT_Path:" 2  1 "" 2  15  20  0  2>"${SERVICEINPUT}"
       local dis_conf_ser=($(<"${SERVICEINPUT}"))
       local vhost_name=${dis_conf_ser[0]}
       local vhost_path=${dis_conf_ser[1]}
       conf_service_nginxvir
       /usr/local/nginx/sbin/nginx -t >/dev/null 2>&1
       if [[ $? -eq 0 ]]
          then
          local s_info="config ${vhost_name} "
          dis_success
       fi
       conf_service
    ;;
    2)
     echo ""
    ;;
    3)
     echo ""
    ;;
esac
}
conf_service_php(){
dialog --backtitle "${backtitle}"  --title "${title}" --menu "Make your decisions" 12 55 3 \
 1 "Add php extension." \
 2 "unknown." 2>"${SERVICEINPUT}"
local dis_conf_ser=$(<"${SERVICEINPUT}")
case ${dis_conf_ser} in
    1)
     cd ${CURRRENT_PATH}
     source ./ext/zendopcache
     source ./ext/redis
     source ./ext/mongo
     dialog --backtitle "${backtitle}" --title "${title}"  --checklist "make your choice?" 20 60 3 \
zendopcache "The PHP code to accelerate the plug-in."  1 \
redis "PHP extension of Redis." 2 \
mongo "PHP extension of MongoDB." 3 2>"${SERVICEINPUT}"
     local ext_rs=($(echo $(<"${SERVICEINPUT}")| sed -ne 's/\"//gp' ))
     for rs in ${ext_rs[@]}
        do
         if [[ ${rs} == 'zendopcache' ]]
            then
              conf_phpext_opcache
         elif [[ ${rs} == 'redis'  ]]
            then
              conf_phpext_redis
         elif [[ ${rs} == 'mongo'  ]]
            then
              conf_phpext_mongo
         fi
     done
     dis_success
     conf_service
    ;;
    2)
     echo ""
    ;;
esac
}
conf_lamp(){
dialog --backtitle "${backtitle}"  --title "${title}" --menu "Make your decisions" 12 55 2 \
 1 "start LAMP." \
 2 "stop LAMP." 2>"${SERVICEINPUT}"
local dis_conf_ser=$(<"${SERVICEINPUT}")
case ${dis_conf_ser} in
   1)
    if [[ $(ps aux|grep httpd|wc -l) -gt 1 ]]
       then 
         dialog --clear --backtitle "${backtitle}" --title "${title}" --msgbox "Apache Has been launched" 10 50
       else
         service httpd start >/dev/null 2>&1
         local s_info="Start apache "
         dis_success
    fi
    if [[ $(ps aux|grep mysql|wc -l) -gt 1 ]]
       then
         dialog --clear --backtitle "${backtitle}" --title "${title}" --msgbox "Mysql Has been launched" 10 50
       else
         service mysqld start  >/dev/null 2>&1
         local  s_info="Start mysql "
         dis_success
    fi
    dis_service 
   ;;
   2)
    if [[ $(ps aux|grep httpd|wc -l) -gt 1 ]]
       then
         service httpd stop >/dev/null 2>&1
         local s_info="Stop apache "
         dis_success
       else
        dialog --clear --backtitle "${backtitle}" --title "${title}" --msgbox "Apache Has not started" 10 50
    fi
    if [[ $(ps aux|grep mysql|wc -l) -gt 1 ]]
       then
         service mysqld stop  >/dev/null 2>&1
         local s_info="Stop mysql "
         dis_success
       else
        dialog --clear --backtitle "${backtitle}" --title "${title}" --msgbox "Mysql Has not started." 10 50
    fi
    dis_service
   ;;
esac
dis_service
}
conf_lnmp(){
dialog --backtitle "${backtitle}"  --title "${title}" --menu "Make your decisions" 12 55 2 \
 1 "start LNMP." \
 2 "stop LNMP." 2>"${SERVICEINPUT}"
local dis_conf_ser=$(<"${SERVICEINPUT}")
case ${dis_conf_ser} in
    1)
     if [[ $(ps aux|grep nginx|wc -l) -gt 1 ]]
       then
         dialog --clear --backtitle "${backtitle}" --title "${title}" --msgbox "NGINX Has been launched" 10 50
       else
         /usr/local/nginx/sbin/nginx >/dev/null 2>&1
         local s_info="Start Nginx "
         dis_success
    fi
    if [[ $(ps aux|grep mysql|wc -l) -gt 1 ]]
       then
         dialog --clear --backtitle "${backtitle}" --title "${title}" --msgbox "MYSQL Has been launched" 10 50
       else
         service mysqld start  >/dev/null 2>&1
         local s_info="Start mysql "
         dis_success
    fi
    if [[ $(ps aux|grep php-fpm|wc -l) -gt 1 ]]
       then
         dialog --clear --backtitle "${backtitle}" --title "${title}" --msgbox "PHP-FPM Has been launched" 10 50
       else
         service php-fpm start  >/dev/null 2>&1
         local s_info="Start PHP-FPM "
         dis_success
    fi
    dis_service
    ;;
    2)
    if [[ $(ps aux|grep nginx|wc -l) -gt 1 ]]
       then
         /usr/local/nginx/sbin/nginx -s stop >/dev/null 2>&1
         local s_info="Stop Nginx "
         dis_success
       else
        dialog --clear --backtitle "${backtitle}" --title "${title}" --msgbox "NGINX Has not started" 10 50
    fi
    if [[ $(ps aux|grep mysql|wc -l) -gt 1 ]]
       then
         service mysqld stop  >/dev/null 2>&1
         local s_info="Stop mysql "
         dis_success
       else
        dialog --clear --backtitle "${backtitle}" --title "${title}" --msgbox "MYSQL Has not started." 10 50
    fi
      if [[ $(ps aux|grep php-fpm|wc -l) -gt 1 ]]
       then
         kill -INT `cat /usr/local/php/var/run/php-fpm.pid`  >/dev/null 2>&1
         local s_info="Stop PHP-FPM "
         dis_success
       else
        dialog --clear --backtitle "${backtitle}" --title "${title}" --msgbox "PHP-FPM Has not started." 10 50
    fi
    dis_service
    ;;
esac
dis_service
}
##########################--------------- echo successful -------------#####################

################################### service config ##############################
dis_service(){
dialog --backtitle "${backtitle}"  --title "${title}" --menu "Make your decisions" 12 55 4 \
 1 "Config SERVICES." \
 2 "Config SELINUX." \
 3 "Start/Stop LAMP." \
 4 "Start/Stop LNMP." 2>"${SERVICEINPUT}"
local dis_ser_c=$(<"${SERVICEINPUT}")
case ${dis_ser_c} in
    1)  conf_service;;
    2)  conf_selinux;;
    3)  conf_lamp;;
    4)  conf_lnmp;;
esac
}

###################################### configure firewall ########################################
conf_fw(){
dialog --backtitle "${backtitle}"  --title "${title}" --menu "Make your decisions" 12 55 5 \
 1 "Only port model." \
 2 "Port and Ipaddress model." \
 3 "Stop iptables" \
 4 "Start  iptables" \
 5 "Restart iptables" 2>"${SERVICEINPUT}"
local dis_ser_fw_c=$(<"${SERVICEINPUT}")
case ${dis_ser_fw_c} in
    1)  conf_fw_pt;;
    2)  conf_fw_ptip;;
    3)  conf_fw_close;;
    4)  conf_fw_start;;
    5)  conf_fw_restart;;
esac
dis_service
}
conf_fw_pt(){
dialog --backtitle "${backtitle}"  --title "${title}" --inputbox "part of by comma like: 22,80,21" 10 30  2>"${SERVICEINPUT}"
local dis_fw_pt_c=$(<"${SERVICEINPUT}")
if [[ $(echo ${dis_fw_pt_c}|grep -Eo "[^0-9|,]" |wc -l) -gt 0 ]] || [[ -z "${dis_fw_pt_c}" ]]
then
   dialog --clear --backtitle "${backtitle}" --title "${title}" --msgbox "Error format like ${dis_fw_pt_c} or empty sting" 10 40
   conf_fw
else
local ports=($(echo ${dis_fw_pt_c}|sed 's/,/ /g'))
dialog --backtitle "${backtitle}"  --title "${title}" --menu "Make your decisions" 12 55 2 \
 1 "Accept port." \
 2 "Deny port." 2>"${SERVICEINPUT}"
local dis_ptad_c=$(<"${SERVICEINPUT}")
case ${dis_ptad_c} in
    1)  confirm_iptable_accept;;
    2)  confirm_iptable_deny;;
esac
fi
}
confirm_iptable_accept(){
dialog  --backtitle "${backtitle}" --title "${title}" --no-shadow --yesno "Are you confirm ? " 8 50
local response_ap=$?
case $response_ap in
    0)  accept_port;;
    1)  conf_fw;;
esac
}
accept_port(){
for port in ${ports[@]}
   do
      iptables -A INPUT -p tcp --dport ${port} -j ACCEPT
done
}
confirm_iptable_deny(){
dialog  --backtitle "${backtitle}" --title "${title}" --no-shadow --yesno "Are you confirm ? " 8 50
local response_dy=$?
case $response_dy in
    0)  deny_port;;
    1)  conf_fw;;
esac
}
deny_port(){
for port in ${ports[@]}
   do
      iptables -A INPUT -p tcp --dport ${port} -j DROP
done
}
conf_fw_close(){
service iptables stop >/dev/null 2>&1
dis_success
}
conf_fw_start(){
service iptables start >/dev/null 2>&1
dis_success
}
conf_fw_restart(){
service iptables restart >/dev/null 2>&1
dis_success
}
dis_success(){
if [[ $? -eq 0 ]]
then
  dialog --clear --backtitle "${backtitle}" --title "${title}" --msgbox "${s_info}Successful!" 10 50
else
  dialog --clear --backtitle "${backtitle}" --title "${title}" --msgbox "Error! \n${e_info}" 10 50
fi
}
#####################################--------------------- CONFIG SELINUX --------------------#######################
conf_selinux(){
dialog --backtitle "${backtitle}"  --title "${title}" --menu "Make your decisions" 12 55 2 \
 1 "Disable selinux." \
 2 "Enable selinux." 2>"${SERVICEINPUT}"
local dis_ser_sl_c=$(<"${SERVICEINPUT}")
case ${dis_ser_sl_c} in
    1)
     sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
     setenforce 0 
     dis_success	 
	;;
    2)
     if [[ $(echo $(grep "SELINUX=enforcing" /etc/selinux/config|wc -l)) -gt 0 ]]
		then 
		    local e_info="SELINUX is enforcing"
		    dis_success
		else
		    sed -i 's/SELINUX=disabled/SELINUX=enforcing/g' /etc/selinux/config  
			setenforce 1
			dis_success
	 fi
	;;
esac
dis_service
}
####################################------------------ install service --------------------##########################
dis_install(){
dialog --backtitle "${backtitle}"  --title "${title}" --menu "Make your decisions" 12 55 4 \
 1 "Yum install LAMP." \
 2 "Source install LNMP." \
 3 "Install System management tools." 2>"${INSTALLINPUT}"
local dis_inst_c=$(<"${INSTALLINPUT}")
case ${dis_inst_c} in
    1)  inst_lamp_yum;;
    2)  inst_lnmp_source;;
    3)  inst_sys_tools;;
esac
}
########################################################

#########################################################
inst_lnmp_source_download(){
sum=10
if [[ -d ${source_dir} ]]
then  
    mkdir -p ${source_dir}
fi
cd ${source_dir}
for s in {http://ftp.gnu.org/pub/gnu/libiconv/libiconv-1.13.1.tar.gz,http://downloads.sourceforge.net/mcrypt/libmcrypt-2.5.8.tar.gz,http://nchc.dl.sourceforge.net/project/mhash/mhash/0.9.9.9/mhash-0.9.9.9.tar.gz,http://pkgs.fedoraproject.org/repo/pkgs/mcrypt/mcrypt-2.6.8.tar.gz/97639f8821b10f80943fa17da302607e/mcrypt-2.6.8.tar.gz,http://mirrors.sohu.com/mysql/MySQL-5.5/mysql-5.5.53.tar.gz,wget http://mirrors.sohu.com/php/php-5.6.9.tar.gz,http://nginx.org/download/nginx-1.4.7.tar.gz,http://ftp.cs.stanford.edu/pub/exim/pcre/pcre-8.33.tar.gz}
   do
      if [[ ! -f ${s##*/} ]];then
          sleep 1
          wget -q -P ${source_dir} ${s}
      fi
      let sum=${sum}+10
      echo "$sum"
done |dialog --clear --backtitle "${backtitle}" --title " Waiting for download.....  " --gauge "Download completion... " 8 50
}

############################################################
inst_lnmp_source(){
source ./bin/libiconv
source ./bin/libmcrypt
source ./bin/mhash
source ./bin/php
source ./bin/mysql
source ./bin/nginx
sum=0
for soft in {gcc,gcc-c++,autoconf,libjpeg-turbo,libjpeg-turbo-devel,libpng,libpng-devel,freetype,freetype-devel,libxml2,libxml2-devel,zlib,zlib-devel,glibc,glibc-devel,glib2,glib2-devel,bzip2,bzip2-devel,ncurses,ncurses-devel,curl,curl-devel,e2fsprogs,e2fsprogs-devel,krb5-devel,libidn,libidn-devel,openssl,openssl-devel,openldap,openldap-devel,openldap-clients,openldap-servers,wget}
    do
        let sum=${sum}+3
	rpm -q ${soft} >/dev/null 2>&1
        if [[ $? -gt 0 ]]
           then
              yum install -y ${soft} >/dev/null 2>&1
        fi
	if [[ ${sum} -gt 100 ]]
	    then
		echo "100"
	    else
		echo "${sum}"
	fi
done | dialog --clear --backtitle "${backtitle}" --title " Waiting for install Initialize the software..... " --gauge "Yum install completion ↓ " 8  60
inst_lnmp_source_download
dialog --backtitle "${backtitle}" --title "${title}"  --checklist "Which do you want install,make your choice?" 20 60 3 \
mysql   "install mysql-5.5.29" 1 \
php     "install php-5.3.28." 2 \
nginx   "install nginx-1.4.7." 3  2>"${INSTALLINPUT}"
local lnmp_rs=($(echo $(<"${INSTALLINPUT}")| sed -ne 's/\"//gp' ))
for rs in ${lnmp_rs[@]}
    do
     if [[ ! -d /usr/local/${rs} ]] && [[ ${rs} == 'mysql'  ]]
       then
         dialog --clear --backtitle "${backtitle}" --title "${title}" --msgbox "Begin install ${rs}!" 10 50
         inst_lnmp_mysql
     elif [[ ! -d /usr/local/${rs} ]] && [[ ${rs} == 'php' ]]
       then
         dialog --clear --backtitle "${backtitle}" --title "${title}" --msgbox "Begin install ${rs}!" 10 50
         inst_lnmp_source_libiconv
	     inst_lnmp_source_libmcrypt
         inst_lnmp_source_mhash
         inst_lnmp_php
     elif [[ ! -d /usr/local/${rs} ]] && [[ ${rs} == 'nginx' ]]
       then
         dialog --clear --backtitle "${backtitle}" --title "${title}" --msgbox "Begin install ${rs}!" 10 50
         inst_lnmp_nginx
     else
        dialog --clear --backtitle "${backtitle}" --title "${title}" --msgbox "${rs} Already installed!" 10 50
     fi
done
dis_install
}
###############################################################
inst_lamp_yum(){
count=0
for rpb in gcc gcc-c++ make zlib-devel libtool ncurses-devel libxml2-devel httpd httpd-devel mysql mysql-server mysql-devel php php-mysql php-common php-gd php-mbstring php-cli php-devel php-xml
    do
        rpm -q ${rpb} >/dev/null 2>&1
        if [[ $? -gt 0 ]]
            then
                yum install -y ${rpb} >/dev/null 2>&1
        fi
        let count=${count}+5
        echo ${count}
done | dialog --clear --backtitle "${backtitle}" --title " Waiting for init.....  " --gauge "Yum install completion ${rpb} " 8 50
dis_succes
#dialog  --backtitle "${backtitle}" --title "${title}" --no-shadow --yesno "Do want configure your LAMP service now ? " 8 50
#local response_ym=$?
#case $response_ym in
#    0)  conf_lamp_yum_service;;
#    1)  dis_main;;
#esac
}
##############################################################
inst_sys_tools(){
dialog --backtitle "${backtitle}" --title "${title}"  --checklist "Which do you want drop,make your choice?" 20 60 10 \
iftop   "Used to monitor the host traffic." 1 \
iotop   "Used to monitor the host disk." 2 \
strace  "Used to monitor the process." 3 \
lsof    "Used to monitor the process open files." 4 \
tcpdump "Used to capture data packets."  5 \
tcpflow "Used to capture http requests." 6  2>"${INSTALLINPUT}"
local tl_rs=($(echo $(<"${INSTALLINPUT}")| sed -ne 's/\"//gp' ))
for rs in ${tl_rs[@]}
    do
        rpm -q ${rs} >/dev/null 2>&1
	if [[ $? -gt 0 ]]
       	    then
                local s_info="${rs} install "
                local e_info="${rs} install failed."
                yum install -y ${rs} >/dev/null 2>&1
                dis_success
        fi
done
}
#####################################------------------------  backup -------------------------------############################
dis_backup(){
dialog --backtitle "${backtitle}"  --title "${title}" --menu "Make your decisions" 12 55 2 \
 1 "backup sourcecode." \
 2 "backup mysql." 2>"${BACKUPINPUT}"
local dis_back_c=$(<"${BACKUPINPUT}")
case ${dis_back_c} in
  1) dis_backup_source;;
  2) dis_backup_mysql;;
esac
}
dis_backup_source(){
dialog  --backtitle "${backtitle}" --title "${title}" --form "plase input file or directory path and Backup file name:" 12 50 3  \
"Path:" 1  1 "" 1  15  20  0  \
"Name:" 2  1 "" 2  15  20  0  2>"${BACKUPINPUT}"
local dis_backup_c=($(<"${BACKUPINPUT}"))
if [[ $(echo ${#dis_backup_c[@]}) -eq 2 ]]
   then
      tar -jpcf /tmp/${dis_backup_c[1]}-"$(date +'%Y%m%d')".tar.bz2 ${dis_backup_c[0]}
      dis_success
fi
}
dis_backup_mysql(){
dialog --backtitle "${backtitle}"  --title "${title}" --menu "Make your decisions" 12 55 2 \
 1 "import data." \
 2 "export data." 2>"${BACKUPINPUT}"
local dis_back_c=$(<"${BACKUPINPUT}")
case ${dis_back_c} in
  1)
   while true
   do
      dialog --title "Pick your sql file" --fselect /root/ 7 50 2>"${BACKUPINPUT}"
      local dis_back_c=$(<"${BACKUPINPUT}")
      if [[ -f ${dis_back_c}  ]]
       then
          dialog --backtitle "${backtitle}"  --title "${title}" --insecure --passwordbox  "Please input root passwd" 10 40  2>"${BACKUPINPUT}"
          local dis_root_pwd=$(<"${BACKUPINPUT}")
          ${MYSQL_PATH}/mysql -uroot -p${dis_root_pwd}  -e "show databases" > ${BACKUPINPUT}
          if [[ $? -eq 0  ]]
             then
                dialog --backtitle "${backtitle}" --title "${title}"   --menu "Which database do you want?" 20 50 10 $(awk 'BEGIN{ORS='\n'}NR>2{print $0," DBname_of_"$0" "}' ${BACKUPINPUT} ) 2>${BACKUPINPUT}
                local dis_db_nm=$(<"${BACKUPINPUT}")
                dialog --clear --backtitle "${backtitle}" --title "${title}" --msgbox "begin to import data,wait a few minutes...(:" 10 50
                ${MYSQL_PATH}/mysql -uroot -p${dis_root_pwd} ${dis_db_nm} < ${dis_back_c} 
                dis_success
             else
               dialog --clear --backtitle "${backtitle}" --title "${title}" --msgbox "root password is error." 10 50
               dis_backup
          fi
          break
      fi
      dialog --clear --backtitle "${backtitle}" --title "${title}" --msgbox "your choice a directory not sql files." 10 50
   done
   dis_backup
   ;;
  2)
    dialog --backtitle "${backtitle}"  --title "${title}" --insecure --passwordbox  "Please input root passwd" 10 40  2>"${BACKUPINPUT}"
    local dis_root_pwd=$(<"${BACKUPINPUT}")
    ${MYSQL_PATH}/mysql -uroot -p${dis_root_pwd}  -e "show databases" > ${BACKUPINPUT}
    dialog --backtitle "${backtitle}" --title "${title}"  --checklist "Which do you want drop,make your choice?" 20 50 10 $(awk 'BEGIN{ORS='\n'}NR>2{print $0,"Database_"$0,NR-2" "}' ${BACKUPINPUT} ) 2>${BACKUPINPUT}
    local dbname_rs=($(echo $(<"${BACKUPINPUT}")| sed -ne 's/\"//gp' ))
    for rs in ${dbname_rs[@]}
      do
        local s_info="Congratulations export database ${rs} "
        local e_info="Check your password or maybe database ${rs} is not exsit "
       ${MYSQL_PATH}/mysqldump -uroot -p${dis_root_pwd} ${rs} > ${CURRRENT_PATH}/${rs}_"$(date +'%Y%m%d')".sql
        dis_success
    done
  ;;
esac
}
#####################################------------ dis main ----------- #######################################################
dis_main(){
dialog --clear --help-button --backtitle "${backtitle}" \
    --title "${title}" \
    --menu "You can use the UP/DOWN arrow keys to Choose the TASK" 20 50 8 \
    Report "CHECK HOST INFOMATION AS A REPORT." \
    Network "CONFIGURATION NETWORK." \
    Install "Install SERVICES. " \
    Service "CONFIG YOUR HOST SERVER." \
    Disk "TEST YOUR DISK SPEED." \
    Cmd  "RUN COMMAND TO THE REMOTE HOST." \
    Backup "FOR BACKUP DATAS." \
    Exit "EXIT TO THE SHELL" 2>"${INPUT}"
menuitem=$(<"${INPUT}")
}

############################-------------------- check env----------- ###############################
check_environment(){
for rp in hdparm expect dialog dmidecode openssh-clients
    do
       rpm -q ${rp} >/dev/null 2>&1
       if [[ $? -gt 0 ]]
       then
              yum install -y ${rp} >/dev/null 2>&1
       fi
done
}
check_environment
#######################################################################
while true
do
    dis_main
    case $menuitem in
        Report)    dis_info;;
        Network)   dis_network;;
        Install)   dis_install;;
        Service)   dis_service;;
        Disk)      dis_disk;;
        Cmd)       dis_cmd;;
        Backup)    dis_backup;;
        Exit)    echo "Bye";break;;
    esac
done
rm -rf /tmp/*.sh.*
#[ -f ${tmp_file} ] && rm ${tmp_file}
#[ -f $INPUT ] && rm $INPUT
