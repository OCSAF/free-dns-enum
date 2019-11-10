#!/bin/bash

###########################################################
################### OCSAF Free DNSENUM ####################
###########################################################

################################################################################################
#  FROM THE FREECYBERSECURITY.ORG TESTING-PROJECT (GNU-GPLv3) - https://freecybersecurity.org  #
#  With this script DNS information can be extracted and monitored.                            #
#                                                                                              #
#  Use only with legal authorization and at your own risk! ANY LIABILITY WILL BE REJECTED!     #
#                                                                                              #
#  Script programming by Mathias Gut, Netchange Informatik GmbH under GNU-GPLv3.               #
#  Uses BASH, DIG, HOST, GEOIPLOOKUP, TheHarvester - https://github.com/laramies/theHarvester  #
#                                                                                              #
#  Special thanks to Tore (cr33y) for creating the checklists.                                 #
#  Thanks to the community and also for your personal project support.                         #
################################################################################################

#######################
### Preparing tasks ###
#######################


#Check if a program is installed.

_program=(dig host geoiplookup theHarvester)

for i in "${_program[@]}"; do
	if [ -z $(command -v ${i}) ]; then
		echo "${i} is not installed."
		_count=1
	fi
done
	if [[ ${_count} -eq 1 ]]; then
		exit
	fi

unset _program
unset _count

#Read current date and time in hours and minutes into variable.
_TIME=$(date +%d.%m.%Y-%H:%M)

#Check if a folder exists and create otherwise.
if ! [ -d "./free_enums" ]; then
	mkdir ./free_enums
fi

if ! [ -d "./free_temp/" ]; then
	mkdir ./free_temp/
fi

###############################
### EXAMPLE TOOL USAGE TEXT ###
###############################

funcHelp() {
	echo "From the Free OCSAF project"
	echo "Free OCSAF DNSENUM 0.1 - GPLv3 (https://freecybersecurity.org)"
	echo "Use only with legal authorization and at your own risk!"
       	echo "ANY LIABILITY WILL BE REJECTED!"
       	echo ""
	echo "USAGE:"
	echo "  ./freednsenum.sh -d <domain> -l <list>"
	echo "  ./freednsenum.sh -n <name> -l <list>"
       	echo ""
	echo "EXAMPLE:"
       	echo "  ./freednsenum.sh -d freecybersecurity.org -l subdomainslist.txt"
       	echo "  ./freednsenum.sh -d freecybersecurity.org -l subdomainslist.txt -t 2.5"
       	echo "  ./freednsenum.sh -n freecybersecurity -l toplevel.txt"
       	echo ""
	echo "OPTIONS:"
	echo "  -h, help - this beautiful text"
	echo "  -d <domain> - the domain to check"
	echo "  -n <name> - the name to check the toplevel domains"
	echo "  -l <list> - subdomain or toplevel domain list to check"
	echo "  -t <seconds> - time between queries"
	echo "  -g, geoip - shows country"
	echo "  -o, osint - dns enumeration with theHarvester tool (dnsdumpster, crtsh)"
	echo "  -v, verbose - shows additional information like alias etc."
	echo "  -w, whois ip"
	echo "  -z, zero - delete free_enums-files"
	echo "  -c, no color scheme set"
       	echo ""
	echo "NOTES:"
	echo "#See also the MAN PAGE - https://freecybersecurity.org"
}

###############################
### GETOPTS - TOOL OPTIONS  ###
###############################

while getopts "d:n:l:t:govwzhc" opt; do
	case ${opt} in
		h) funcHelp; exit 1;;
		d) _DOMAIN="$OPTARG"; _CHECKARG1=1;;
		n) _NAME="$OPTARG"; _CHECKARG1=1;;
		l) _LIST="$OPTARG"; _CHECKARG2=1;;
		t) _WAIT="$OPTARG";;
		g) _GEOIP=1;;
		o) _OSINT=1;;
		v) _VERBOSE=1;;
		w) _WHOIS=1;;
		z) _ZERO_DEL=1;;
		c) _COLORS=1;;
		\?) echo "**Unknown option**" >&2; echo ""; funcHelp; exit 1;;
        	:) echo "**Missing option argument**" >&2; echo ""; funcHelp; exit 1;;
		*) funcHelp; exit 1;;
  	esac
  	done
	shift $(( OPTIND - 1 ))

#Check if _CHECKARG1 is not set
if [ "${_CHECKARG1}" == "" ] && [ "${_ZERO_DEL}" == "" ]; then
	echo "**No domain or name set**"
	echo ""
	funcHelp
	exit 1
fi

#Check if _CHECKARG2 or _OSINT is not set
if [ "${_CHECKARG2}" == "" ] && [ "${_ZERO_DEL}" == "" ] && [ "${_OSINT}" == "" ]; then
	echo "**Missing list [-l] or OSINT parameter [-o]**"
	echo ""
	funcHelp
	exit 1
fi

#Check if wait is set
if [ "${_WAIT}" == "" ]; then
	_WAIT=0.2
fi

#Zero - delete all free_enums files
if [ "${_ZERO_DEL}" == "1" ]; then
	touch ./free_enums/delete_${_TIME}
	touch ./free_temp/delete_${_TIME}
	rm -rf ./free_enums/*
	rm -rf ./free_temp/*
	echo "########################################################"
	echo "####  ./free_enums/ and ./free_temp/ FILES DELETED  ####"
	echo "########################################################"
	echo ""
	exit 1
fi

###############
### COLORS  ###
###############

#Colors directly in the script.

if [[ ${_COLORS} -eq 1 ]]; then
	cOFF=''
	rON=''
	gON=''
	yON=''
else
	cOFF='\e[39m'	  #color OFF / Default color
	rON='\e[31m'	  #red color ON
	gON='\e[32m'	  #green color ON
	yON='\e[33m'	  #yellow color ON
fi

#############################
### freednsenum functions ###
#############################

funcDNSEnumA() {

	local _subdomain=${1}
	local _domain=${_DOMAIN}
	local _ip=${_IP}
	local _whois=${_WHOIS}
	local _geoip=${_GEOIP}
	local _verbose=${_VERBOSE}
	local _time=${_TIME}
	local _acheck
	local _alist
	local _subcheck
	local _aliascheck
	local _aliascheck2
	local _noacheck
	local _inetnum
	local _netname
	local _orgname
	local _country
	local _route
	local _geoip_country
	local _geoip_countrycode
	local _line
	
	host -t a ${_subdomain}.${_domain} > ./free_temp/acheck_${_subdomain}_${_domain}_${_time}.txt
	
	_alist=./free_temp/acheck_${_subdomain}_${_domain}_${_time}.txt
	
	_acheck=$(cat ./free_temp/acheck_${_subdomain}_${_domain}_${_time}.txt)
	_subcheck=$(echo ${_acheck} \
		| grep -v Host \
		| grep -v alias \
		| grep -v "no A record" \
		| grep -i "${_subdomain}.${_domain} has address" \
		| cut -d " " -f4)
	_aliascheck=$(echo ${_acheck} \
		| grep -i alias)
	_noacheck=$(echo ${_acheck} \
		| grep -i "no A record")

	if [ "${_ip}" != "${_subcheck}" ] || [ "${_subdomain}" == "www" ]; then
		if [ "${_subcheck}" != "" ]; then
			if ! [ -d "./free_enums/${_domain}" ]; then
				mkdir ./free_enums/${_domain}
			fi
			
			echo -e "${yON}${_subcheck} ${_subdomain}.${_domain} active${cOFF}"
			
			echo ${_subcheck} >> ./free_enums/${_domain}/ip_list_${_domain}.txt
			sort -u ./free_enums/${_domain}/ip_list_${_domain}.txt \
				-o ./free_enums/${_domain}/ip_list_${_domain}.txt

			if [ "${_geoip}" == "1" ]; then
				echo "GEOIP [${_subcheck}]:"
				_geoip_country=$(geoiplookup ${_subcheck} | cut -d " " -f5)
				_geoip_countrycode=$(geoiplookup ${_subcheck} | cut -d " " -f4 | cut -d "," -f1)
				echo "|_ ${_geoip_country} (${_geoip_countrycode})"
			fi

			if [ "${_whois}" == "1" ]; then

				whois ${_subcheck} > ./free_enums/${_domain}/whois_${_subdomain}_${_domain}.txt
				
				_whoisfile="./free_enums/${_domain}/whois_${_subdomain}_${_domain}.txt"
				_inetnum=$(cat ${_whoisfile} \
					| grep -i 'inetnum\|netrange')
				_netname=$(cat ${_whoisfile} \
					| grep -i netname)
				_orgname=$(cat ${_whoisfile} \
					| grep -i -m1 'org-name\|orgname\|descr')
				_country=$(cat ${_whoisfile} \
					| grep -i country)
				_route=$(cat ${_whoisfile} \
					| grep -v mnt-route \
					| grep -i -m1 'route\|cidr')
			
				echo "WHOIS [${_subcheck}]:"
				echo "|_ ${_inetnum}"
				echo "|_ ${_orgname}"
				echo "|_ ${_netname}"
				echo "|_ ${_country}"
				echo "|_ ${_route}"
			fi
			echo ""
		fi
	fi
	
	if [ "${_verbose}" != "" ]; then
		if [ "${_aliascheck}" != "" ]; then
			echo -e "${yON}${_subdomain}.${_domain} is an alias for${cOFF}"
			#geoiplookup ${_subdomain}.${_domain}
			while read _line
			do
				_aliascheck2=$(echo ${_line} \
					| grep -i "${_subdomain}.${_domain} is an alias" \
					| cut -d " " -f6)
				if [ "${_aliascheck2}" != "" ]; then
					echo "${_aliascheck2}"

					if [ "${_geoip}" == "1" ]; then
						echo "GEOIP [${_aliascheck2}]:"
						_geoip_country=$(geoiplookup ${_aliascheck2} | cut -d " " -f5)
						_geoip_countrycode=$(geoiplookup ${_aliascheck2} | cut -d " " -f4 | cut -d "," -f1)
						echo "|_ ${_geoip_country} (${_geoip_countrycode})"
					fi	
				fi
				unset _line
			done < ${_alist}
			echo ""
		fi
	
		if [ "${_noacheck}" != "" ]; then
			echo -e "${yON}${_noacheck}${cOFF}"
			echo ""
		fi
	fi

	rm ${_alist}
}

funcTLDEnumA() {

	local _tld=${1}
	local _domain=${_DOMAIN}
	local _name=${_NAME}
	local _time=${_TIME}
	local _acheck
	local _subcheck
	local _aliascheck
	
	_acheck=$(host -t a ${_name}${_tld})
	_subcheck=$(echo ${_acheck} \
		| grep -v alias \
		| grep -i "has address" \
		| cut -d " " -f4)
	_aliascheck=$(echo ${_acheck} \
		| grep -i alias)

	if [ "${_subcheck}" != "" ]; then
		echo "${_name}${_tld} (${_subcheck}) active"
	fi

	if [ "${_aliascheck}" != "" ]; then
			echo -e "${yON}${_aliascheck}${cOFF}"
	fi
}

funcHarvesterDNS() {
	#Thanks to TheHarvester - https://github.com/laramies/theHarvester
	local _time=${_TIME}
	local _domain=${_DOMAIN}
	local _i
	local _dns_enum_list
	local _dns_enum
	local _dns_checked
	local _dns_num

	if ! [ -d "./free_enums/${_domain}" ]; then
		mkdir ./free_enums/${_domain}
	fi

	theHarvester -d ${_DOMAIN} -b dnsdumpster,crtsh \
		| grep -v '[*]' | grep : | grep -i ${_domain} \
	       	> ./free_temp/osint_${_domain}_${_time}.txt

	_dns_enum_list=./free_temp/osint_${_domain}_${_time}.txt
	
	_dns_enum=$(cat ./free_temp/osint_${_domain}_${_time}.txt)
	
	if [ "${_dns_enum[*]}" != "" ]; then
		cat ./free_temp/osint_${_domain}_${_time}.txt \
			| grep -v ^${_domain}: \
			| awk -F ".${_domain}:" '{print $1}' \
			> ./free_enums/${_domain}/osint_${_domain}_${_time}.txt

		for ((_i=0;_i<${#_dns_enum[*]};_i++))
		do 
			_dns_checked+=($(echo ${_dns_enum[$_i]}))
		done
	
		_dns_num=$(echo ${_dns_checked[*]} | wc -w)
		
		if [ "${_dns_checked[*]}" != "" ]; then
			if [ "${_dns_checked[1]}" == "" ]; then
				echo -e "${yON}$_dns_num host found for the domain ${_domain}${cOFF}"
			else
				echo -e "${yON}$_dns_num hosts found for the domain ${_domain}${cOFF}"
			fi

			for ((i=0;i<${#_dns_checked[*]};i++))
			do 
				echo  ${_dns_checked[$i]}
			done	
			
			echo ""	
			echo -e "${yON}Found subdomains for the following analysis stored in [use -l]:${cOFF}" 
			echo "|_ [./free_enums/${_domain}/osint_${_domain}_${_time}.txt]"
		fi
	
	else
		echo -e "${gON}No hosts found with DNS enumeration.${cOFF}"
	fi
	
	rm ${_dns_enum_list}
}

############
### MAIN ###
############

echo ""
echo "##########################################"
echo "####  FREE OCSAF DNSENUM GPLv3        ####"
echo "####  https://freecybersecurity.org   ####"
echo "####  Version 0.1 (10.11.19)          ####"
echo "##########################################"
echo ""

if [ "${_DOMAIN}" != "" ] && [ "${_OSINT}" == "" ]; then
	_IP=$(dig +short -t a ${_DOMAIN})
	echo -e "${gON}Test for ${_DOMAIN} with the IP ${_IP}:${cOFF}"
	echo ""
	while read _line
	do
		funcDNSEnumA ${_line}
		unset _line
		sleep ${_WAIT}
	done <${_LIST}
	if [ -d "./free_enums/${_domain}" ]; then
		echo -e "${yON}All found IPs were saved in:${cOFF}" 
		echo "|_ [./free_enums/${_DOMAIN}/ip_list_${_DOMAIN}.txt]"
		echo ""
	fi
elif [ "${_OSINT}" != "" ]; then
	echo -e "${gON}Test for ${_DOMAIN} with theHarvester (dnsdumpster, crtsh):${cOFF}"
	echo ""
	funcHarvesterDNS
	echo ""
elif [ "${_NAME}" != "" ]; then
	echo -e "${gON}Test active a record for the name - ${_NAME}:${cOFF}"
	echo ""
	while read _line
	do
		funcTLDEnumA ${_line}
		unset _line
		sleep ${_WAIT}
	done <${_LIST}
	echo ""
fi

################### END ###################
