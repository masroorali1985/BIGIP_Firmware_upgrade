#!/bin/bash
# ========================================================================================================
# Name .........: f5-check.sh
#
# Description ..: Shell script to provide overview information on BIG-IP (and BIG-IQ) and check system
#                 health
#
# Author .......: Gregor Dicke, F5 Networks GmbH, M: +49 173 731 3884, E: g.dicke@f5.com
#
#
# Version | Date       | Author          | Description
# --------+------------+-----------------+--------------------------------------------------------------
# 001     | 2021-03-16 | Gregor Dicke    | Initial version
# 002     | 2021-03-17 | Gregor Dicke    | Added failover status time + ntp status heuristics
# 003     | 2021-03-23 | Gregor Dicke    | Fixed S/N on BIG-IP device issue (Appliance || Chassis)
#         |            |                 | Fixed Failover Status issue for Standby BIG-IP
#         |            |                 | Fixed division by zero error when no VS and Pool exist
# 004     | 2021-03-23 | Gregor Dicke    | Added DNS config check
# 005     | 2021-03-25 | Gregor Dicke    | Allow MCP status "high-config-load-succeed"
# 006     | 2021-04-15 | Gregor Dicke    | Added service start check (in addition to the existing
#         |            |                 | restarts check) and re-added Secure Vault Master Key (f5mku)
# 007     | 2021-04-20 | Gregor Dicke    | Modified service starts heuristic
# 008     | 2021-04-20 | Gregor Dicke    | Fixed issue with detection of service starts
# 009     | 2021-04-20 | Gregor Dicke    | Added file system checks and modified grep string for
#         |            |                 | service starts
# 010     | 2021-04-29 | Gregor Dicke    | Added hardware related checks for VIPRION and BIG-IP
# 011     | 2021-05-05 | Gregor Dicke    | Added display of BIG-IP Management IP
# 012     | 2021-05-06 | Gregor Dicke    | Added option to use remote execution via iControl REST API
# 013     | 2021-05-17 | Gregor Dicke    | Fixed issue with Sync Status warning via iControl REST
# 014     | 2021-08-23 | Gregor Dicke    | Added CRIT level notifications
# 015     | 2021-08-26 | Gregor Dicke    | Modified notification for power supply not present to OK
# 016     | 2021-09-02 | Gregor Dicke    | Added Cores + RAM info and BIG-IP platform type
# 017     | 2021-11-30 | Gregor Dicke    | Added CPU and clock rate info
# 018     | 2022-02-01 | Gregor Dicke    | Removed check of filesystems starting with "/var/apm/mount",
#         |            |                 | as outlined in https://support.f5.com/csp/article/K55431021
# 019     | 2022-02-17 | Gregor Dicke    | Added SSL Cert Check tests
# 020     | 2022-04-11 | Gregor Dicke    | Added "base-config-load-succeed" as OK for mcp status
# 021     | 2022-04-12 | Gregor Dicke    | Excluded filesystem "/usr" from df check due to K23607394
#         |            |                 |
#
# ========================================================================================================

# ----------------------------------------------------------------------------------------
# Variables
#
version=021
timestamp=$(date +"%Y-%m-%d %H:%M:%S")
today=$(date +"%Y-%m-%d")
epoch=$(date +%s)

  # Distinguish between local and remote execution
  #bas
  if [ $# -eq 0 -a -f /usr/bin/tmsh ]
    then

      # Local execution on BIG-IP
      #
      hostname=$HOSTNAME
      tssv=$(tmsh show sys version)
      tssh=$(tmsh show sys hardware)
      tlsm=$(tmsh list sys management-ip one-line)
      tslprov=$(tmsh list sys provision one-line)
      tssl=$(tmsh show sys license field-fmt)
      tssps=$(tmsh show sys performance system raw)
      tssm=$(tmsh show sys memory raw field-fmt)
      tsspc=$(tmsh show sys performance connections raw)
      tsspt=$(tmsh show sys performance throughput raw)
      tssmcp=$(tmsh show sys mcp field-fmt)
      tscf=$(tmsh show cm failover-status)
      tssf=$(tmsh show sys failover)
      tssha=$(tmsh show sys ha-status)
      tlct=$(tmsh list cm trust-domain)
      tscs=$(tmsh show cm sync-status)
      tsni=$(tmsh show net interface raw)
      tsnt=$(tmsh show net trunk raw field-fmt)
      tslv=$(tmsh -c "cd / ; show ltm virtual recursive field-fmt")
      tslp=$(tmsh -c "cd / ; show ltm pool recursive field-fmt")
      tlsfsc=$(tmsh -c "cd / ; list sys file ssl-cert recursive" | awk -v OFS=";" '$1 == "sys" && $2 == "file" && $3 == "ssl-cert" { cert = "/" $4 } $1 == "expiration-date" { print cert , $2 }')
      tsss=$(tmsh show sys service)
      tlsd=$(tmsh list sys dns all-properties)
      tsshff=$(tmsh show sys hardware field-fmt)
      ntpqn=$(ntpq -pn)
      df=$(df)
      dfi=$(df -i)
      fvcwc=$(find /var/core/ -xdev -type f | wc -l)

      management_ip=$(echo "$tlsm" | cut -d " " -f 3)
      platform=$(echo "$tssh" | awk -v hit=0 '$1 == "Platform" { hit = 1 } $1 == "Name" && hit == 1 { gsub ( "^ * Name *" , "" , $0 ) ; print $0 }')
      type=$(echo "$tssh" | awk -v hit=0 '$1 == "System"  && $2 == "Information" { hit = 1 } $1 == "Type" && hit == 1 { gsub ( "^ * Type *" , "" , $0 ) ; print $0 ; exit }')
      modules=$(echo "$tslprov" | egrep " level " | cut -d " " -f 3 | tr "a-z" "A-Z" | paste -d "," -s - | sed "s/,/, /g")
      serial_number=$(echo "$tssh" | awk '( $1 == "Chassis" || $1 == "Appliance" ) && $2 == "Serial" { print $3 }')
      secure_vault_master_key=$(f5mku -K)

    else

        # Print help
        #
        if [ $# -ne 2 -a $# -ne 3 ]
          then
            echo
            echo "  Option 1: Local execution, relying on tmsh"
            echo "  ------------------------------------------"
            echo "   # f5-check.sh"
            echo
            echo
            echo "  Option 2: Remote execution, relying on iControl REST API"
            echo "  --------------------------------------------------------"
            echo "   # f5-check.sh <IP_or_hostname> <username> [<password>]"
            echo
            exit 1
        fi

      # Remote execution
      #
      bigip=$1
      username=$2
      password=$3
      which curl >/dev/null 2>&1
        [ $? -ne 0 ] && echo -e "\n  Error: Command \"curl\" not available!\n" && exit 2
      which jq >/dev/null 2>&1
        [ $? -ne 0 ] && echo -e "\n  Error: Command \"jq\" not available!\n" && exit 3
      curl -kI --connect-timeout 1 https://$bigip/ >/dev/null 2>&1
        [ $? -ne 0 ] && echo -e "\n  Error: Can not access \"https://$bigip\"!\n" && exit 4
      curl -kI https://$bigip/mgmt/tm/ 2>/dev/null | egrep -q "F5 Authorization Required"
        [ $? -ne 0 ] && echo -e "\n  Error: BIG-IP iControl REST API not accessible via \"https://$bigip/mgmt/tm/\"!\n" && exit 5
        [ $# -eq 2 ] && echo -e "Password: \c" && read -s password && echo
      token=$(curl -k https://$bigip/mgmt/shared/authn/login -d "{ "username":"$username","password":"$password","loginProviderName":"tmos" }" 2>/dev/null | jq -r .token.token)
        [ ! "$token" -o "$token" == "null" ] && echo -e "\n  Error: Could not obtain token from \"https://$bigip/mgmt/shared/authn/login\" for user \"$username\"!\n" && exit 6

      hostname=$(curl -kH "X-F5-Auth-Token: $token" https://$bigip/mgmt/tm/sys/global-settings 2>/dev/null | jq -r ".hostname")
      management_ip=$(curl -kH "X-F5-Auth-Token: $token" https://$bigip/mgmt/tm/sys/management-ip 2>/dev/null | jq -r ".items[].fullPath")
      tssv=$(curl -kH "X-F5-Auth-Token: $token" https://$bigip/mgmt/tm/sys/version 2>/dev/null | jq -r '.entries."https://localhost/mgmt/tm/sys/version/0".nestedStats.entries' | sed -e :GD -e '$!N;s/: {\n *\"description\": */ /;tGD' -e 'P;D' | egrep "\"" | tr -d "\"")
      tssh=$(curl -kH "X-F5-Auth-Token: $token" https://$bigip/mgmt/tm/sys/hardware 2>/dev/null)
      platform=$(echo "$tssh" | jq -r '.entries."https://localhost/mgmt/tm/sys/hardware/platform".nestedStats.entries."https://localhost/mgmt/tm/sys/hardware/platform/0".nestedStats.entries.marketingName.description')
      type=$(echo "$tssh" | jq -r '.entries."https://localhost/mgmt/tm/sys/hardware/system-info".nestedStats.entries."https://localhost/mgmt/tm/sys/hardware/system-info/0".nestedStats.entries.platform.description')
      serial_number=$(echo "$tssh" | jq -r '.entries."https://localhost/mgmt/tm/sys/hardware/system-info".nestedStats.entries."https://localhost/mgmt/tm/sys/hardware/system-info/0".nestedStats.entries.bigipChassisSerialNum.description')
      modules=$(curl -kH "X-F5-Auth-Token: $token" https://$bigip/mgmt/tm/sys/provision 2>/dev/null | jq -r ".items[]|.fullPath,.level" | pr -2 -a -t -s";" | egrep -v ";none$" | cut -d ";" -f 1 | tr "a-z" "A-Z" | paste -d "," -s - | sed "s/,/, /g")
      tssl=$(curl -kH "X-F5-Auth-Token: $token" https://$bigip/mgmt/tm/sys/license 2>/dev/null | jq -r '.entries."https://localhost/mgmt/tm/sys/license/0".nestedStats.entries|{"registration-key":.registrationKey.description,"service-check-date":.serviceCheckDate.description}' | tr -d "\":,")
      secure_vault_master_key=$(curl -kH "X-F5-Auth-Token: $token" -H "Content-Type: application/json" -X POST  -d '{"command": "run", "utilCmdArgs": "-c \"/usr/local/bin/f5mku -K\""}' https://$bigip/mgmt/tm/util/bash 2>/dev/null | jq -r ".commandResult")
      tssps=$(curl -kH "X-F5-Auth-Token: $token" https://$bigip/mgmt/tm/sys/performance/system 2>/dev/null | jq -r '.entries."https://localhost/mgmt/tm/sys/performance/system/Utilization".nestedStats.entries.Current.description' | sed "s/^/Utilization /g")
      tssm=$(curl -kH "X-F5-Auth-Token: $token" https://$bigip/mgmt/tm/sys/memory 2>/dev/null | jq -r '.entries."https://localhost/mgmt/tm/sys/memory/memory-host".nestedStats.entries[].nestedStats.entries|{"memory-total":."memoryTotal".value,"memory-used":."memoryUsed".value}' | tr -d "\":,")
      tsspc=$(curl -kH "X-F5-Auth-Token: $token" https://$bigip/mgmt/tm/sys/performance/connections 2>/dev/null | jq -r '.entries|{"Client Connections":."https://localhost/mgmt/tm/sys/performance/connections/Client%20Connections".nestedStats.entries.Current.description,"Connections":."https://localhost/mgmt/tm/sys/performance/connections/Connections".nestedStats.entries.Current.description,"Server Connections":."https://localhost/mgmt/tm/sys/performance/connections/Server%20Connections".nestedStats.entries.Current.description}' | tr -d "\":,")
      tsspt=$(curl -kH "X-F5-Auth-Token: $token" -H "Content-Type: application/json" -X POST  -d '{"command": "run", "utilCmdArgs": "-c \"tmsh show sys performance throughput raw\""}' https://$bigip/mgmt/tm/util/bash 2>/dev/null | jq -r ".commandResult")
      tssmcp=$(curl -kH "X-F5-Auth-Token: $token" -H "Content-Type: application/json" -X POST  -d '{"command": "run", "utilCmdArgs": "-c \"tmsh show sys mcp field-fmt\""}' https://$bigip/mgmt/tm/util/bash 2>/dev/null | jq -r ".commandResult")
      tssha=$(curl -kH "X-F5-Auth-Token: $token" https://$bigip/mgmt/tm/sys/performance/connections 2>/dev/null | jq . | egrep "^ *\"description\": " | pr -4 -a -t -s" "  | tr -d "\"" | awk '{ print $8 , $6 , $2 , $4 }')
      tlct=$(curl -kH "X-F5-Auth-Token: $token" https://$bigip/mgmt/tm/cm/trust-domain 2>/dev/null | jq -r ".items[].status" | sed "s/^/status /g")
      tscf=$(curl -kH "X-F5-Auth-Token: $token" https://$bigip/mgmt/tm/cm/failover-status 2>/dev/null | jq -r '.entries."https://localhost/mgmt/tm/cm/failover-status/0".nestedStats.entries|{"Color":.color.description,"Status":.status.description}' | tr -d "\":,")
      tssf=$(curl -kH "X-F5-Auth-Token: $token" https://$bigip/mgmt/tm/sys/failover 2>/dev/null | jq -r ".apiRawValues.apiAnonymous")
      tscs=$(curl -kH "X-F5-Auth-Token: $token" https://$bigip/mgmt/tm/cm/sync-status 2>/dev/null | jq -r '.entries."https://localhost/mgmt/tm/cm/sync-status/0".nestedStats.entries|{"Color":.color.description,"Status":.status.description,"Mode":.mode.description}' | tr -d "\":,")
      tsni=$(curl -kH "X-F5-Auth-Token: $token" https://$bigip/mgmt/tm/net/interface/stats 2>/dev/null | jq "." | egrep "^ *\"(value|description)\": " | pr -9 -a -t -s" " | tr -d "\"" | awk '{ print $16 , $18 , $2 , $4 , $10 , $12 , $6 , $8 , $14 }')
      tsnt=$(curl -kH "X-F5-Auth-Token: $token" https://$bigip/mgmt/tm/net/trunk/stats 2>/dev/null | jq -r '.entries."https://localhost/mgmt/tm/net/trunk/my_trunk/stats".nestedStats.entries|{"counters.errors-in":."counters.errorsIn".value,"counters.errors-out":."counters.errorsOut".value,"status":.status.description}' | tr -d "\":," | egrep -v " null$")
      tslv=$(curl -kH "X-F5-Auth-Token: $token" https://$bigip/mgmt/tm/ltm/virtual/stats 2>/dev/null | jq -r '.entries[].nestedStats.entries|{"status.availability-state":."status.availabilityState".description," status.enabled-state":."status.enabledState".description}' 2>/dev/null | tr -d "\":,")
      tslp=$(curl -kH "X-F5-Auth-Token: $token" https://$bigip/mgmt/tm/ltm/pool/stats 2>/dev/null | jq -r '.entries[].nestedStats.entries|{"status.availability-state":."status.availabilityState".description," status.enabled-state":."status.enabledState".description}' 2>/dev/null | tr -d "\":,")
      tlsfsc=$(curl -kH "X-F5-Auth-Token: $token" https://$bigip/mgmt/tm/sys/file/ssl-cert 2>/dev/null | jq -r '.items[]|.fullPath,.expirationDate' | pr -2 -a -t -s";")
      fvcwc=$(curl -kH "X-F5-Auth-Token: $token" -H "Content-Type: application/json" -X POST  -d '{"command": "run", "utilCmdArgs": "-c \"find /var/core/ -xdev -type f | wc -l\""}' https://$bigip/mgmt/tm/util/bash 2>/dev/null | jq -r ".commandResult")
      tsss=$(curl -kH "X-F5-Auth-Token: $token" https://$bigip/mgmt/tm/sys/service/stats 2>/dev/null | jq -r '.apiRawValues.apiAnonymous')
      ntpqn=$(curl -kH "X-F5-Auth-Token: $token" -H "Content-Type: application/json" -X POST  -d '{"command": "run", "utilCmdArgs": "-c \"ntpq -pn\""}' https://$bigip/mgmt/tm/util/bash 2>/dev/null | jq -r ".commandResult")
      tlsd=$(curl -kH "X-F5-Auth-Token: $token" https://$bigip/mgmt/tm/sys/dns 2>/dev/null | jq -r '.' | awk 'BEGIN { ns = "none" ; search = "none" } $1 == "\"nameServers\":" { ns = "configured" } $1 == "\"search\":" { search = "configured" } END { print "name-servers" , ns ; print "search" , search}') # {"name-servers":.nameServers[],"search":.search[]}' | tr -d "\":,")
      df=$(curl -kH "X-F5-Auth-Token: $token" -H "Content-Type: application/json" -X POST  -d '{"command": "run", "utilCmdArgs": "-c \"df\""}' https://$bigip/mgmt/tm/util/bash 2>/dev/null | jq -r ".commandResult")
      dfi=$(curl -kH "X-F5-Auth-Token: $token" -H "Content-Type: application/json" -X POST  -d '{"command": "run", "utilCmdArgs": "-c \"df -i\""}' https://$bigip/mgmt/tm/util/bash 2>/dev/null | jq -r ".commandResult")
      tsshff=$(curl -kH "X-F5-Auth-Token: $token" -H "Content-Type: application/json" -X POST  -d '{"command": "run", "utilCmdArgs": "-c \"tmsh show sys hardware field-fmt\""}' https://$bigip/mgmt/tm/util/bash 2>/dev/null | jq -r ".commandResult")

  fi


# Logic applicable both to local and remote execution
#
software_version=$(echo "$tssv" | awk '$1 == "Product" { product = $2 } $1 == "Version" { version = $2 } $1 == "Build" { build = $2 } $1 == "Edition" { if ( $2 == "Final" ) build = $2 ; if ( $2 == "Engineering" && $3 == "Hotfix" ) build = "EngHF " build ; if ( $2 == "Point" && $3 == "Release" ) build = "Build " build } END { print product " " version " " build }')
baseregkey=$(echo "$tssl" | awk '$1 == "registration-key" { gsub ( "\"" , "" , $2 ) ; print $2 }')
cpuutil=$(echo "$tssps" | awk '$1 == "Utilization" { status = "[ OK ]" ; if ( $2 >= 80 ) status = "[WARN]" ; if ( $2 == 100 ) status = "[CRIT]" ; print status " " $2 "%, warn at >= 80%, crit at 100%" }')
memutil=$(echo "$tssm" | awk '$1 == "memory-total" { total = $2 } $1 == "memory-used" { memutil = int ( $2 / total * 100 ) ; status = "[ OK ]" ; if ( memutil >= 90) { status = "[WARN]" ; if ( memutil == 100 ) status = "[CRIT]" } } END { print status " " memutil "%, warn at >= 90%, crit at 100%" }')
connections=$(echo "$tsspc" | awk '$1 == "Connections" { threshold = 1 ; status = "[ OK ]" ; if ( $2 <= threshold ) status = "[WARN]" ; print status " " $2 " connections, warn at <= " threshold }')
clientconns=$(echo "$tsspc" | awk '$1 == "Client" { threshold = 0 ; status = "[ OK ]" ; if ( $3 <= threshold ) status = "[WARN]" ; print status " " $3 " connections, warn at <= " threshold }')
serverconns=$(echo "$tsspc" | awk '$1 == "Server" { threshold = 0 ; status = "[ OK ]" ; if ( $3 <= threshold ) status = "[WARN]" ; print status " " $3 " connections, warn at <= " threshold }')
throughputin=$(echo "$tsspt" | awk '$1 == "In" { threshold = 1000 ; status = "[ OK ]" ; if ( $2 <= threshold ) status = "[WARN]" ; print status " " $2 " bits, warn at <= " threshold ; exit }')
throughputout=$(echo "$tsspt" | awk '$1 == "Out" { threshold = 1000 ; status = "[ OK ]" ; if ( $2 <= threshold ) status = "[WARN]" ; print status " " $2 " bits, warn at <= " threshold ; exit }')
mcpstatus=$(echo "$tssmcp" | awk '$1 == "last-load" { lastload = $2 } $1 == "phase" { status = "[ OK ]" ; if ( $2 != "running" || ( lastload != "full-config-load-succeed" && lastload != "high-config-load-succeed" && lastload != "base-config-load-succeed" ) ) status = "[CRIT]" ; print status " " $2 " - "  lastload }')
hafailurestatus=$(echo "$tssha" | awk 'BEGIN { status = "[ OK ] no failure" } $NF == "yes" { status = "[CRIT] " $1 " \"" $2 "\" failed" } END { print status }')
trustdomstatus=$(echo "$tlct" | awk '$1 == "status" { status = "[ OK ]" ; if ( $2 != "standalone" && $2 != "initialized" ) status = "[WARN]" ; print status " " $2 }')
failoverstatus=$(echo "$tscf" | awk '$1 == "Color" { color = $2 } $1 == "Status" { status = "[ OK ]" ; if ( ( color != "green" && color != "gray" ) || ( $2 != "ACTIVE" && $2 != "STANDBY" ) ) status = "[WARN]" ; print status " " color " - " $2 }')
failoverstatustime=$(echo "$tssf" | awk '{ status = "[ OK ]" ; if ( $4 == "0d" ) { status = "[WARN]" ; if ( $5 ~ /^00:/ ) status = "[CRIT]" } ; print status " " $0 ", warn at <= 0d, crit at <= 1h" }')
syncstatus=$(echo "$tscs" | awk '$1 == "Color" { color = $2 } $1 == "Status" { stat = $0 ; gsub ( "^ *Status  *" , "" , stat ) } $1 == "Mode" { status = "[ OK ]" ; if ( color != "green" || ( stat != "Standalone" && stat != "In Sync" ) || ( $2 != "high-availability" && $2 != "standalone" ) ) status = "[WARN]" ; print status " " color " - " stat " - " $2 }')
intups=$(echo "$tsni" | awk 'BEGIN { intups = 0 ; status = "[ OK ]" } $2 == "up" { intups ++ } END { threshold = 1 ; if ( intups <= threshold ) status = "[CRIT]" ; print status " " intups " interfaces up, crit at <= " threshold }')
interrs=$(echo "$tsni" | awk 'BEGIN { errs = 0 ; status = "[ OK ]" } $2 == "up" { errs = errs + $8 } END { threshold = 0 ; if ( errs > threshold ) status = "[WARN]" ; print status " " errs " interface errors, warn at > " threshold }')
intdropspct=$(echo "$tsni" | awk 'BEGIN { threshold = 0.01 ; status = "[ OK ] less than " threshold "% interface drops on all up interfaces" } $2 == "up" { total = $3 + $4 ; drops = $7 ; dropspct = drops / total * 100 ; if ( dropspct > threshold ) { status = "[WARN] " dropspct "% interface drops, warn at > " threshold "%" ; exit } } END { print status }')
trunkstatus=$(echo "$tsnt" | awk 'BEGIN { status = "[ OK ] either no trunks configured or trunks up and without errors" ; hit = 0 } $1 == "counters.errors-in" && $2 != "0" { hit = 1 } $1 == "counters.errors-out" && $2 != "0" { hit = 1 } $1 == "status" && $2 != "up" { hit = 1 } END { if ( hit == 1 ) status = "[CRIT] Trunks not up or with errors" ; print status }')
vsstatus=$(echo "$tslv" | awk 'BEGIN { oks = 0 ; totals = 0 ; status = "[ OK ]" } $1 == "status.availability-state" { as = $2 } $1 == "status.enabled-state" { totals ++ ; if ( as == "available" && $2 == "enabled" ) oks ++ } END { okspct = 0 ; if ( oks > 0 ) okspct = oks / totals * 100 ; threshold = 10 ; if ( okspct <= threshold ) status = "[WARN]" ; print status " " okspct "% of " totals " available and enabled, warn at <= 10%" }')
poolstatus=$(echo "$tslp" | awk 'BEGIN { oks = 0 ; totals = 0 ; status = "[ OK ]" } $1 == "status.availability-state" { as = $2 } $1 == "status.enabled-state" { totals ++ ; if ( as == "available" && $2 == "enabled" ) oks ++ } END { okspct = 0 ; if ( oks > 0 ) okspct = oks / totals * 100 ; threshold = 10 ; if ( okspct <= threshold ) status = "[WARN]" ; print status " " okspct "% of " totals " available and enabled, warn at <= 10%" }')
sslcertstatus=$(echo "$tlsfsc" | awk -v EPOCH="$epoch" -F ";" 'BEGIN { status = "[ OK ] No SSL certs expired within 24h or due to expire within 24h" ; dte = 0 ; ae = 0 } { diff = $2 - EPOCH ; if ( diff > 0 && diff <= 86400 ) dte ++ ; if ( diff <= 0 && diff >= -86400 ) ae ++ } END { if ( dte > 0 ) status = "[WARN] " dte " SSL cert(s) due to expire within 24h" ; if ( ae > 0 ) status = "[CRIT] " ae " SSL cert(s) expired within 24h, " dte " due to expire within 24h" ; print status }')
corestatus=$(echo "$fvcwc" | awk '{ status = "[ OK ] no core files in /var/core/" ; if ( $1 != 0 ) status = "[CRIT] " $1 " core file(s) in /var/core/" ; print status }')
servicestarts=$(echo "$tsss" | awk 'BEGIN { status = "[ OK ] no recent service starts, warn at <= 1d, crit at <= 1h" } /) [0-9]+ (second|minute)(s)?, [0-9]+ start/ { status = "[CRIT] service(s) with start(s) within less than 1 hour" ; exit } /) [0-9]+ hour(s)?, [0-9]+ start/ { status = "[WARN] service(s) with start(s) within less than 24 hours" } END { print status }')
servicerestarts=$(echo "$tsss" | awk 'BEGIN { status = "[ OK ] no recent service restarts, warn at <= 1d, crit at <= 1h" } /) [0-9]+ (second|minute)(s)?, [0-9]+ restart/ { status = "[CRIT] service(s) with restart(s) within less than 1 hour" ; exit } /) [0-9]+ hour(s)?, [0-9]+ restart/ { status = "[WARN] service(s) with restart(s) within less than 24 hours" } END { print status }')
licscd=$(echo "$tssl" | awk -v TODAY="$today" '$1 == "service-check-date" { threshold = 365 ; status = "[ OK ]" ; gsub ( "\"" , "" , $2 ) ; split ( $2 , dateA , "/" ) ; scdnum = ( int ( ( dateA[1] - ( dateA[2] < 3 ? 1969 : 1968 ) ) * 1461 / 4 ) + int ( ( 153 * ( dateA[2] + ( dateA[2] < 3 ? 9 : -3 ) ) +2 ) / 5 ) + dateA[3] - 672 ) ; split ( TODAY , dateA , "-" ) ; todaynum = ( int ( ( dateA[1] - ( dateA[2] < 3 ? 1969 : 1968 ) ) * 1461 / 4 ) + int ( ( 153 * ( dateA[2] + ( dateA[2] < 3 ? 9 : -3 ) ) +2 ) / 5 ) + dateA[3] - 672 ) ; gsub ( "/" , "-" , $2 )  ; if ( ( todaynum - scdnum ) >= threshold ) status = "[WARN]" ; print status " " $2 " is " ( todaynum - scdnum ) " days old, warn at >= " threshold " days" }')
ntpstatus=$(echo "$ntpqn" | awk 'BEGIN { status = "[WARN] NTP has no peer" } /^\*/ { gsub ( "\\*" , "" , $1 ) ; status = "[ OK ] NTP has peer " $1 } END { print status }')
dnsstatus=$(echo "$tlsd" | awk '$1 == "name-servers" && $2 == "none" { hit = 1 } $1 == "search" && $2 == "none" { hit = 1 } END { if ( hit == 1 ) { print "[WARN] DNS config missing name-servers or search domain" } else { print "[ OK ] DNS properly configured" } }')
fsfreestatus=$(echo "$df" | awk 'BEGIN { status = "[ OK ] all relevant FS with free space, warn at >= 95%, crit at 100%" } $6 ~ /^\// && $NF !~ /^\/var\/apm\/mount\// && $NF != "/usr" { if ( ( $3 / ( $3 + $4 ) * 100 ) >= 95 ) { status = "[WARN] filesystem(s) with space in use at >= 95%" ; if ( ( $3 / ( $3 + $4 ) * 100 ) == 100 ) { status = "[CRIT] filesystem(s) with space in use at 100%" ; exit } } } END { print status }')
fsinodestatus=$(echo "$dfi" | awk 'BEGIN { status = "[ OK ] all FS with free inodes, warn at >= 95%, crit at 100%" } $6 ~ /^\// && $NF !~ /^\/var\/apm\/mount\// { if ( ( $3 / ( $3 + $4 ) * 100 ) >= 95 ) { status = "[WARN] filesystem(s) with inodes in use at >= 95%" ; if ( ( $3 / ( $3 + $4 ) * 100 ) == 100 ) { status = "[CRIT] filesystem(s) with inodes in use at 100%" ; exit } } } END { print status }')
tsshffol=$(echo "$tsshff" | sed -e :GD -e '$!N;s/\n\([ }]\)/ \1/;tGD' -e "s/  */ /g" -e "P;D")
cpu=$(echo "$tsshffol" | egrep "^sys hardware hardware-version cpus " | sed "s/^.* model \(.*\) name .* versions.2.version \([0-9][0-9]*\)\.[0-9][0-9]* versions.3.name .*$/\1 \/ \2 MHz/g")
cores=$(echo "$tsshffol" | egrep "^sys hardware hardware-version cpus " | sed "s/^.* versions.1.version \([0-9][0-9]*\)  *\(.*\) versions.2.name .*$/\1 Cores \2/g")
ram=$(echo "$tssm" | awk '$1 == "memory-total" { gb = int ( $2 / 1024 / 1024 / 1024 + 1 ) ; if ( gb > 124 && gb < 128 ) gb = 128 ; if ( gb > 251 && gb < 256 ) gb = 256 ; print gb , "GB" ; exit }')
powerstatus=$(echo "$tsshffol" | awk '$3 == "chassis-power-supply-status-index" { status = "[ OK ] all power supplies up" ; for ( i = 6 ; i < NF ; i++ ) { if ( $i == "status" && $(i+1) != "up" ) { if ( $(i+1) == "not-present" ) { status = "[ OK ] power supplies up but at least one not present" } else { status = "[CRIT] at least one power supply not up" ; exit } } } } END { print status }')
chassisfanstatus=$(echo "$tsshffol" | awk '$3 == "chassis-fan-status-index" { status = "[ OK ] all chassis fans up" ; for ( i = 6 ; i < NF ; i++ ) { if ( $i == "status" && $(i+1) != "up" ) { status = "[CRIT] at least one chassis fan not up" ; exit } } } END { print status }')
chassisfanspeed=$(echo "$tsshffol" | awk '$3 == "chassis-fan-status-index" && / fan-speed / && / lo-limit / { for ( i = 6 ; i < NF ; i++ ) { if ( $i == "lo-limit" ) lowlimit = $(i+1) } ; status = "[ OK ] speed of all chassis fans OK, warn at <= " lowlimit ;  for ( i = 6 ; i < NF ; i++ ) { if ( $i == "fan-speed" && $(i+1) <= lowlimit ) { status = "[CRIT] speed of at least one chassis fan low, crit at <= " lowlimit ; exit } } } END { print status }')
bladetempstatus=$(echo "$tsshffol" | awk '$3 == "blade-temperature-status-index" { for ( i = 6 ; i < NF ; i++ ) { if ( $i == "hi-limit" ) highlimit = $(i+1) } ; status = "[ OK ] temperature for all blade sensors OK" ;  if ( $(NF-1) >= highlimit ) { status = "[CRIT] temperature of at least one blade sensor too high, crit at >= " highlimit ; exit } } END { print status }')
cpufanspeed=$(echo "$tsshffol" | awk '$3 == "cpu-status-index" { lowlimit = 1000 ; status = "[ OK ] speed of all cpu fans OK, crit at <= " lowlimit ;  for ( i = 6 ; i < NF ; i++ ) { if ( $i == "fan-speed" && $(i+1) <= lowlimit ) { status = "[CRIT] speed of at least one cpu fan low, crit at <= " lowlimit ; exit } } } END { print status }')
cputempstatus=$(echo "$tsshffol" | awk '$3 == "cpu-status-index" { highlimit = 65 ; status = "[ OK ] temperature for all cpu sensors OK" ; if ( $(NF-1) >= highlimit ) { status = "[CRIT] temperature of at least one cpu sensor too high, crit at >= " highlimit ; exit } } END { print status }')
chassistempstatus=$(echo "$tsshffol" | awk '$3 == "chassis-temperature-status-index" { for ( i = 6 ; i < NF ; i++ ) { if ( $i == "hi-limit" ) highlimit = $(i+1) } ; status = "[ OK ] temperature for all chassis sensors OK" ;  if ( $(NF-1) >= highlimit ) { status = "[CRIT] temperature of at least one chassis sensor too high, crit at >= " highlimit ; exit } } END { print status }')
slotstatus=$(echo "$tsshffol" | awk '$3 == "slot-status-index" { status = "[ OK ] all slots either powered up or unpopulated" ; for ( i = 6 ; i < NF ; i++ ) { if ( $i == "status" && $(i+1) != "powered-up" && $(i+1) != "unpopulated" ) { status = "[CRIT] at least one slot not powered up and unpopulated" ; exit } } } END { print status }')


# ----------------------------------------------------------------------------------------
# Output - Header
#
us="Overview:" ; echo -e "\n$us\n$us" | sed "3s/./=/g"
echo "Hostname .........................: $hostname"
echo "Management IP ....................: $management_ip"
echo "Software Version .................: $software_version"
echo "Platform .........................: $platform ($type)"
echo "CPU / Clock Rate .................: $cpu"
echo "Cores / RAM ......................: $cores / $ram"
echo "Modules Provisioned ..............: $modules"
echo "Serial Number (S/N) ..............: $serial_number"
echo "Base Registration Key ............: $baseregkey"
echo "Secure Vault Master Key ..........: $secure_vault_master_key"

# ----------------------------------------------------------------------------------------
# Output - Health Checks
#
us="Health Checks:" ; echo -e "\n$us\n$us" | sed "3s/./=/g"
echo "CPU Utilization ..................: $cpuutil"
echo "Memory Utilization ...............: $memutil"
echo "Connections ......................: $connections"
echo "Client Connections ...............: $clientconns"
echo "Server Connections ...............: $serverconns"
echo "Throughput (In) ..................: $throughputin"
echo "Throughput (Out) .................: $throughputout"
echo "MCP State ........................: $mcpstatus"
echo "HA Failure Status ................: $hafailurestatus"
echo "Trust Domain Status ..............: $trustdomstatus"
echo "Failover Status ..................: $failoverstatus"
echo "Failover Status Time .............: $failoverstatustime"
echo "Sync Status ......................: $syncstatus"
echo "Network Interfaces up ............: $intups"
echo "Errors on Interfaces .............: $interrs"
echo "Drops on Interfaces ..............: $intdropspct"
echo "Trunk Status .....................: $trunkstatus"
echo "Virtual Server Status ............: $vsstatus"
echo "Pool Member Status ...............: $poolstatus"
echo "SSL Certificate Status ...........: $sslcertstatus"
echo "Core File Status .................: $corestatus"
echo "Service Start Status .............: $servicestarts"
echo "Service Restart Status ...........: $servicerestarts"
echo "License Service Check Date .......: $licscd"
echo "NTP Status .......................: $ntpstatus"
echo "DNS Status .......................: $dnsstatus"
echo "Filesystem Free Status ...........: $fsfreestatus"
echo "Filesystem Inode Status ..........: $fsinodestatus"
  [ "$powerstatus" ] && echo "Power Supply Status ..............: $powerstatus"
  [ "$chassisfanstatus" ] && echo "Chassis Fan Status ...............: $chassisfanstatus"
  [ "$chassisfanspeed" ] && echo "Chassis Fan Speed ................: $chassisfanspeed"
  [ "$bladetempstatus" ] && echo "Blade Temperature Status .........: $bladetempstatus"
  [ "$cpufanspeed" ] && echo "CPU Fan Speed ....................: $cpufanspeed"
  [ "$cputempstatus" ] && echo "CPU Temperature Status ...........: $cputempstatus"
  [ "$chassistempstatus" ] && echo "Chassis Temperature Status .......: $chassistempstatus"
  [ "$slotstatus" ] && echo "Slot Status ......................: $slotstatus"

# ----------------------------------------------------------------------------------------
# Output - Important
#
echo
echo "IMPORTANT:"
echo " * Heuristics, parameters and thresholds have been defined arbitrarily"
echo " * \"[ OK ]\" messages don't necessarily indicate absence of issues. Further investigation will be required"
echo " * \"[CRIT]\" and \"[WARN]\" messages don't necessarily indicate issues. Further investigation will be required"
echo " * Please use the F5 iHealth service available via https://ihealth.f5.com for reliable diagnostics"
echo

# ----------------------------------------------------------------------------------------
# Output - Footer
#
echo "Report generated at $timestamp / Script Version $version"
echo
