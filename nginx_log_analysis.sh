#!/usr/bin/env bash

echo ""
echo " ========================================================= "
echo "\ Nginx log security analysis script V1.0 /"
echo " ========================================================= "
echo "# Support Nginx log analysis, attack alarm analysis, etc."
echo " # author：al0ne                    "
echo " # https://github.com/al0ne                    "
echo -e "\n"


outfile=/tmp/logs

if [ -d $outfile ]; then
    rm -rf $outfile/*
else
    mkdir -p $outfile
be

access_dir=/var/log/nginx/

access_log=access

num=$(ls ${access_dir}${access_log}* | wc -l) >/dev/null 2>&1
if [ $num -eq 0 ]; then
    echo 'The log file does not exist'
    exit 1
be
echo -e "\n"


OS = 'None'
if [ -e "/etc/os-release" ]; then
    source /etc/os-release
    case ${ID} in
    "debian" | "ubuntu" | "devuan")
        OS = 'Debian'
        ;;
    "centos" | "rhel fedora" | "rhel")
        OS = 'Hundreds'
        ;;
    *) ;;
    esac
be

if [ $OS = 'None' ]; then
    if command -v apt-get >/dev/null 2>&1; then
        OS = 'Debian'
    elif command -v yum >/dev/null 2>&1; then
        OS = 'Hundreds'
    else
        echo -e "\ nThis system is not supported \ n"
        echo -e "Exited"
        exit 1
    be
be


if ag -V >/dev/null 2>&1; then
    echo -e "\ e [00; 32msilversearcher-ag is installed \ e [00m"
else
    if [ $OS = 'Centos' ]; then
        yum -y install the_silver_searcher >/dev/null 2>&1
    else
        apt-get -y install silversearcher-ag >/dev/null 2>&1
    be

be


echo "Analysis Results Log: $ {outfile}"
echo "Nginx log directory: $ {access_dir}"
echo "Nginx file name: $ {access_log}"
echo -e "\n"

echo -e "\ e [00; 31m [+] TOP 20 IP address \ e [00m"
ag -a -o --nofilename '\d+\.\d+\.\d+\.\d+' ${access_dir}${access_log}* | sort | uniq -c | sort -nr | head -n 20 | tee -a ${outfile}/top20.log
echo -e "\n"

echo -e "\ e [00; 31m [+] SQL injection attack analysis \ e [00m"

ag -a "xp_cmdshell|%20xor|%20and|%20AND|%20or|%20OR|select%20|%20and%201=1|%20and%201=2|%20from|%27exec|information_schema.tables|load_file|benchmark|substring|table_name|table_schema|%20where%20|%20union%20|%20UNION%20|concat\(|concat_ws\(|%20group%20|0x5f|0x7e|0x7c|0x27|%20limit|\bcurrent_user\b|%20LIMIT|version%28|version\(|database%28|database\(|user%28|user\(|%20extractvalue|%updatexml|rand\(0\)\*2|%20group%20by%20x|%20NULL%2C|sqlmap" ${access_dir}${access_log}* | ag -v '/\w+\.(?:js|css|html|jpg|jpeg|png|htm|swf)(?:\?| )' | awk '($9==200)||($9==500) {print $0}' >${outfile}/sql.log
awk '{print "SQL injection attack" NR "times"}' $ {outfile} /sql.log | tail -n1
echo "SQL injection TOP 20 IP address"
ag -o '(?<=:)\d+\.\d+\.\d+\.\d+' ${outfile}/sql.log | sort | uniq -c | sort -nr | head -n 20 | tee -a ${outfile}/sql_top20.log

echo "SQL injection FROM query"
cat ${outfile}/sql.log | ag '\bfrom\b' | ag -v 'information_schema' >${outfile}/sql_from_query.log
awk '{print "SQL注入FROM查询" NR"次"}' ${outfile}/sql_from_query.log | tail -n1
echo -e "\n"

echo -e "\ e [00; 31m [+] scanner scan & hacking tools \ e [00m"
ag -a "acunetix|by_wvs|nikto|netsparker|HP404|nsfocus|WebCruiser|owasp|nmap|nessus|HEAD /|AppScan|burpsuite|w3af|ZAP|openVAS|.+avij|.+angolin|360webscan|webscan|XSS@HERE|XSS%40HERE|NOSEC.JSky|wwwscan|wscan|antSword|WebVulnScan|WebInspect|ltx71|masscan|python-requests|Python-urllib|WinHttpRequest" ${access_dir}${access_log}* | ag -v '/\w+\.(?:js|css|jpg|jpeg|png|swf)(?:\?| )' | awk '($9==200)||($9==500) {print $0}' >${outfile}/scan.log
awk '{print "A total of scan attacks were detected" NR "times"}' $ {outfile} /scan.log | tail -n1
echo "TOP 20"
ag -o '(?<=:)\d+\.\d+\.\d+\.\d+' ${outfile}/scan.log | sort | uniq -c | sort -nr | head -n 20 | tee -a ${outfile}/scan_top20.log
echo -e "\n"

echo -e "\ e [00; 31m [+] sensitive path access \ e [00m"
ag -a "/_cat/|/_config/|include=|phpinfo|info\.php|/web-console|JMXInvokerServlet|/manager/html|axis2-admin|axis2-web|phpMyAdmin|phpmyadmin|/admin-console|/jmx-console|/console/|\.tar.gz|\.tar|\.tar.xz|\.xz|\.zip|\.rar|\.mdb|\.inc|\.sql|/\.config\b|\.bak|/.svn/|/\.git/|\.hg|\.DS_Store|\.htaccess|nginx\.conf|\.bash_history|/CVS/|\.bak|wwwroot|备份|/Web.config|/web.config|/1.txt|/test.txt" ${access_dir}${access_log}* | awk '($9==200)||($9==500) {print $0}' >${outfile}/dir.log
awk '{print "A total of NR scans were detected for sensitive files"} "$ {outfile} /dir.log | tail -n1
echo "TOP 20 for sensitive file access"
ag -o '(?<=:)\d+\.\d+\.\d+\.\d+' ${outfile}/dir.log | sort | uniq -c | sort -nr | head -n 20 | tee -a ${outfile}/dir_top20.log
echo -e "\n"

echo -e "\ e [00; 31m [+] exploit detection \ e [00m"
ag -a "%00|/win.ini|/my.ini|\.\./\.\./|/etc/shadow|%0D%0A|file:/|gopher:/|dict:/|WindowsPowerShell|/wls-wsat/|call_user_func_array|uddiexplorer|@DEFAULT_MEMBER_ACCESS|@java\.lang\.Runtime|OgnlContext|/bin/bash|cmd\.exe|wget\s|curl\s|s=/index/\think" ${access_dir}${access_log}* | awk '($9==200)||($9==500) {print $0}' >${outfile}/exploit.log
awk '{print "Exploit exploit" "NR" times "}' $ {outfile} /exploit.log | tail -n1
echo "TOP 20 Exploit Detection"
ag -o '(?<=:)\d+\.\d+\.\d+\.\d+' ${outfile}/exploit.log | sort | uniq -c | sort -nr | head -n 20 | tee -a ${outfile}/exploit_top20.log
echo -e "\n"

echo -e "\e[00;31m[+]webshell\e[00m"
ag -a "=whoami|dbname=|exec=|cmd=|\br57\b|\bc99\b|\bc100\b|\bb374k\b|adminer.php|eval\(|assert\(|%eval|%execute|tunnel\.[asp|php|jsp|aspx]{3,4}|makewebtaski|ma\.[asp|php|jsp|aspx]{3,4}|\bup\.[asp|php|jsp|aspx]{3,4}|cmd\.[asp|php|jsp|aspx]{3,4}|201\d\.[asp|php|jsp|aspx]{3,4}|xiaoma\.[asp|php|jsp|aspx]{3,4}|shell\.[asp|php|jsp|aspx]{3,4}|404\.[asp|php|jsp|aspx]{3,4}|tom\.[asp|php|jsp|aspx]{3,4}|k8cmd\.[asp|php|jsp|aspx]{3,4}|ver[0-9]{3,4}\.[asp|php|jsp|aspx]{3,4}|\.aar|[asp|php|jsp|aspx]{3,4}spy\.|o=vLogin|aioshell|admine|ghost\.[asp|php|jsp|aspx]{3,4}|r00ts|90sec|t00ls|editor\.aspx|wso\.[asp|aspx]{3,4}" ${access_dir}${access_log}* | awk '($9==200)||($9==500) {print $0}' >${outfile}/webshell.log
awk '{print "A total of webshell behavior detected" NR "次"}' $ {outfile} /webshell.log | tail -n1
echo "Webshell TOP 20"
ag -o '(?<=:)\d+\.\d+\.\d+\.\d+' ${outfile}/webshell.log | sort | uniq -c | sort -nr | head -n 20 | tee -a ${outfile}/webshell_top20.log
echo -e "\n"

echo -e "\e[00;31m[+]HTTP Tunnel\e[00m"
#Regeorg Agent Features
ag -a "cmd=disconnect|cmd=read|cmd=forward|cmd=connect|127.0.0.1" ${access_dir}${access_log}* | awk '($9==200)||($9==500) {print $0}' | tee -a ${outfile}/tunnel.log
awk '{print "Total tunnel behavior detected" NR "次"}' $ {outfile} /tunnel.log | tail -n1
echo -e "\n"

echo -e "\ e [00; 31m [+] Top 20 url response length \ e [00m"
# Find the url response with the longest URL sort. The purpose is to download some packaged files from the server.
len=$(cat ${access_dir}${access_log}* | awk '{print $10}' | sort -nr | head -n 20)
echo $len | awk 'BEGIN{ RS=" " }{ print $0 }' | xargs -i{} ag -a --nocolor '\d+\s{}\s' ${access_dir}${access_log}* | awk '{print $7,$10}' | sort | uniq | sort -k 2 -nr | tee -a ${outfile}/url_rsp_len.log
echo -e "\n"

echo -e "\ e [00; 31m [+] rare script file access \ e [00m"
echo "A script file with very few visits is most likely a webshell"
cat ${access_dir}${access_log}* | awk '($9==200)||($9==500) {print $7}' | sort | uniq -c | sort -n | ag -v '\?' | ag '\.php|\.jsp|\.asp|\.aspx' | head -n 20 | tee -a ${outfile}/rare_url.log
echo -e "\n"

echo -e "\ e [00; 31m [+] 302 jump \ e [00m"
echo "The purpose is to find some script files for successful login"
cat ${access_dir}${access_log}* | awk '($9==302)||($9==301) {print $7}' | sort | uniq -c | sort -n | ag -v '\?' | ag '\.php|\.jsp|\.asp|\.aspx' | head -n 20 | tee -a ${outfile}/302_goto.log
echo -e "\n"