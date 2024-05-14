#/bin/bash

# Created by Vinicius Clemente
# Automation script pentest tools

echo "###########################"
echo "	CLEQUILL TOOL			"
echo "###########################"

echo "##########################"
echo "	Testing Tools			"
echo "##########################"

cd archives/

cd Sudomy
./sudomy -h
cd ..

cd ctfr
python3 ctfr.py -h
cd ..

cd Sublist3r
./sublist3r.py -h
cd ..

cd httpx
./httpx -h 
cd ..

cd gau
./gau -h
cd ..

cd gf
./gf -h 
cd ..

cd aquatone
./aquatone -h
cd ..

cd dirsearch
python3 dirsearch.py -h
cd ..

cd SecretFinder
python3 SecretFinder.py -h
cd ..

cd pagodo
python3 pagodo.py -h
cd ..

emailharvester -h

cd go-dork
./go-dork -h
cd ..

h8mail -h

metafinder -h

cd enumerepo
./enumerepo -h 
cd ../../

pwds
#__Main__
#cd ..
pwd
echo "##########################"
echo "	Main			"
echo "##########################"
echo -n "[1] - Subdomain"
echo -n " [2] - Domain"
echo -n " : "
read option

 Option 1
if [ "$option" -eq 1 ]; then
    	echo -n "[1] - Subdomain: "
    	read domain
#    
    	# Verify Directory
    	filename='$domain'

    	if [ -d $filename ]; then
        	echo 'Existe este diretorio $domain'
	else
        	echo ".........."
        	echo "Criando diretorio '$domain'"
        	mkdir $domain
        	echo ".........."
        	echo "Diretorio criado"
        	ls -lt | grep $domain
		cd $domain
		mkdir output
		cd ..
   	fi
	
	cd /home/CleQuill/archives/

	# Run tools
	
	# Sudomy
	cd Sudomy/
	echo "##########################"
	echo "	Running Sudomy		"
	echo "##########################"
	./sudomy -d $domain -o sudomy_$domain
	cd sudomy_$domain/Sudomy-Output/$domain/
	pwd
	#mv subdomain.txt ../../../../../$domain/output/
	#echo "[+] Copy file"

	cd ../../../../
	pwd

#	#Run ctfr
#	cd ctfr/
#	echo "##########################"
#	echo "	Running ctfr		"
#	echo "##########################"
#	python3 ctfr.py -d $domain -o ctfr_$domain.txt
#	mv ctfr_$domain.txt ../../$domain/output/
#
#	echo "[+] Copy file"	cd ..#	# Run Sublist3r
#
#
#	cd Sublist3r
#	echo "##########################"
#	echo "	Running Sublist3r	"
#	echo "##########################"
#	python3 sublist3r.py -d $domain -o sublister_$domain.txt
#	mv sublister_$domain.txt ../../$domain/output/
#	echo "[+] Copy file"
#	cd ..
#
#	echo "##########################"
#	echo "	Running Amass	"
#	echo "##########################"	
#	amass enum -passive -d $domain -o amass-$domain.txt
#
#	# Parse output
#	echo "##########################"
#	echo "	Parsing output files	"
#    echo "##########################"	
#	cd ..
#	cd $domain
#	cd output
#	
#	cat sublister_$domain.txt | sort | uniq >> tmp_all_$domain.txt
#	cat ctfr_$domain.txt | sort | uniq >> tmp_all_$domain.txt
#	cat subdomain.txt | sort | uniq >> tmp_all_$domain.txt
#	mv tmp_all_$domain.txt all_$domain.txt
#
#	# Run HTTPX
#	echo "##########################"
#	echo "	Running HTTPX		"
#	echo "##########################"
#	cd $CAMINHO
#	cd tools/httpx
#	./httpx -l ../../$domain/output/all_$domain.txt  -sc -timeout 15 -cdn -o sc_live_$domain.txt
#	mv sc_live_$domain.txt ../../$domain/output/
#	./httpx -l ../../$domain/output/all_$domain.txt -timeout 15 -o live_$domain.txt
#	mv live_$domain.txt ../../$domain/output
#
#	# Remove Temp files
#	cd $CAMINHO
#	cd $domain/output
#
#	rm sublister_$domain.txt
#	rm ctfr_$domain.txt
#	rm subdomain.txt
#
#	# Run aquatone
#	echo "##########################"
#	echo "	Running Aquatone	"
#	echo "##########################"
#	cat live_$domain.txt | aquatone -chrome-path /opt/google/chrome/google-chrome
#
#
#	# Run Gau
#	echo "##########################"
#	echo "	Running Gau		"
#	echo "##########################"
#	cat live_$domain.txt | gau --verbose --threads 10 > gau_$domain.txt
#
#	
#	# Run Gf
#	mkdir gf
#
#	echo "##########################"
#	echo "	Running Gf		"
#	echo "##########################"
#	cat gau_$domain.txt | gf xss > gf/xss_$domain.txt
#	cat gau_$domain.txt | gf sqli > gf/sqli_$domain.txt
#	cat gau_$domain.txt | gf lfi > gf/lfi_$domain.txt
#	cat gau_$domain.txt | gf http-auth > gf/http-auth_$domain.txt
#	cat gau_$domain.txt | gf idor > gf/idor_$domain.txt
#	cat gau_$domain.txt | gf img-traversal > gf/img-traversal.$domain.txt
#	cat gau_$domain.txt | gf interestingEXT > gd/interestingEXT_$domain.txt
#	cat gau_$domain.txt | gf interestingparams > gf/interestingparams_$domain.txt
#	cat gau_$domain.txt | gf interestingsubs > gf/interestingsubs_$domain.txt
#	cat gau_$domain.txt | gf php-errors > gf/php-errors_$domain.txt
#	cat gau_$domain.txt | gf php-serialized > gf/php-serialized_$domain.txt
#	cat gau_$domain.txt | gf rce > gf/rce_$domain.txt
#	cat gau_$domain.txt | gf redirect > gf/redirect_$domain.txt
#	cat gau_$domain.txt | gf s3-buckets > gf/s3-buckets_$domain.txt
#	cat gau_$domain.txt | gf sec > gf/sec_$domain.txt
#	cat gau_$domain.txt | gf ssrf > gf/ssrf_$domain.txt
#	cat gau_$domain.txt | gf ssti > gf/ssti_$domain.txt
#
# Option 2
else
    	echo -n "[2] - Enter Domain: "
    	read domain
	

#	# Conf. env
#    	cd $CAMINHO
#
#    	# Verify Directory
#    	filename='$domain'
#
#    	if [ -d $filename ]; then
#        	echo '[+] Existe este diretorio $domain'
#    	else
#        	echo "##########################"
#        	echo "	Created '$domain'	"
#		echo "##########################"
#        	mkdir $domain
#        	ls -lt | grep $domain
#		cd $domain
#		mkdir output
#		cd ..
#   	fi
#
#	# Execute tools
#	
#	# Run HTTPX
#        echo "##########################"
#        echo "	Running HTTPX		"
#	echo "##########################"
#        cd $CAMINHO/tools/httpx/
#        ./httpx -u $domain -timeout 15 -o live_$domain.txt
#        mv live_$domain.txt ../../$domain/output
#
#        cd $CAMINHO
#        cd $domain/output
#
#        # Run aquatone
#	echo "##########################"
#        echo "	Running Aquatone	"
#	echo "##########################"
#	cat live_$domain.txt | aquatone -chrome-path /opt/google/chrome/google-chrome
#
#	echo "##########################"
#	echo "	Running Gau		"
#	echo "##########################"
#        cat live_$domain.txt | gau --verbose --threads 10 > gau_$domain.txt
#
#        mkdir gf
#	echo "##########################"
#	echo "	Running Gf		"
#	echo "##########################"
#        cat gau_$domain.txt | gf xss > gf/xss_$domain.txt
#        cat gau_$domain.txt | gf sqli > gf/sqli_$domain.txt
#        cat gau_$domain.txt | gf lfi > gf/lfi_$domain.txt
#        cat gau_$domain.txt | gf http-auth > gf/http-auth_$domain.txt
#        cat gau_$domain.txt | gf idor > gf/idor_$domain.txt
#        cat gau_$domain.txt | gf img-traversal > gf/img-traversal.$domain.txt
#        cat gau_$domain.txt | gf interestingEXT > gf/interestingEXT_$domain.txt
#        cat gau_$domain.txt | gf interestingparams > gf/interestingparams_$domain.txt
#        cat gau_$domain.txt | gf interestingsubs > gf/interestingsubs_$domain.txt
#        cat gau_$domain.txt | gf php-errors > gf/php-errors_$domain.txt
#        cat gau_$domain.txt | gf php-serialized > gf/php-serialized_$domain.txt
#        cat gau_$domain.txt | gf rce > gf/rce_$domain.txt
#        cat gau_$domain.txt | gf redirect > gf/redirect_$domain.txt
#        cat gau_$domain.txt | gf s3-buckets > gf/s3-buckets_$domain.txt
#        cat gau_$domain.txt | gf sec > gf/sec_$domain.txt
#        cat gau_$domain.txt | gf ssrf > gf/ssrf_$domain.txt
#        cat gau_$domain.txt | gf ssti > gf/ssti_$domain.txt
#
#	random=date | awk '{print $4}'
#
#	echo "##########################"
#	echo "	Running Whatweb		"
#	echo "##########################"
#	whatweb $domain --colour=always --user-agent="Bypass_$random" --aggression=3 -v --log-verbose=whatweb_verbose.txt
#
#	echo "##########################"
#	echo "	Running lbd		"
#	echo "##########################"
#	lbd $domain 
#	lbd $domain > lbd_$domain.txt
#
#	echo "##########################"
#	echo "	Running Wafw00f		"
#	echo "##########################"
#	#wafw00f $domain 
#	wafw00f $domain > wafw00f_$domain.txt
#
#	
#	echo "##########################"
#	echo "	Running Imperva-Detect	"
#	echo "##########################"
#	cd imperva-detect
#	./imperva-detect.sh $domain > $domain-imperva-detect.txt
#	./check_ciphers.sh  $domain > $domain-check_ciphers.txt
#	cd ..
#
#	#resposta=$(cat wafw00f_$domain.txt | grep "No WAF detected by the generic detection")
#
#	#if [ $resposta == "No WAF detected by the generic detection" ]; then
#	#	echo "No WAF detected"
#	host $domain | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" > ips_$domain.txt
#	echo "##########################"
#	echo "	Running NMAP		"
#	echo "##########################"
#	nmap -iL ips_$domain.txt -sV -D RND 20 -f --script=vuln -oN nmap_$domain.txt
#	#else
#	#	echo "WAF Detected"
#	#fi
#
#	echo "##########################"
#	echo "	Running WPScan		"
#	echo "##########################"
#	#wpscan --update
#	wpscan --url https://$domain -e at --random-user-agent --api-token LUj8CFzb3m3YffuwsKM1QFoNb5hU2PQOypc8q5V8Xhw  --stealthy  --ignore-main-redirect
#
#	echo "##########################"
#	echo "	Running Nikto		"
#	echo "##########################"
#	nikto -host $domain -useragent="Bypass" 
#
#	echo "##########################"
#	echo "	Running DNSrecon	"
#	echo "##########################"
#	dnsrecon -a -d $domain -v
#	dnsrecon -a -d $domain -v > dnsrecon_$domain.txt
#	
#	echo "##########################"
#	echo "	Running Dirsearch	"
#	echo "##########################"
#	cd $CAMINHO/tools/dirsearch
#	#pip install -r requirements.txt
#	#python3 dirsearch.py -u https://$domain --crawl -o dirsearch_$domain.txt 
# 
#
#	echo "##########################"
#	echo "	Running SecretFinder	"
#	echo "##########################"
#	cd $CAMINHO/tools/SecretFinder
#	#pip install -r requirements.txt 
#	#python3 SecretFinder.py -i https://$domain -e -o $domain.html
#	
#
#	echo "##########################"
#	echo "	CloudFlair		"
#	echo "##########################"
#	cd $CAMINHO/tools/
#	#git clone https://github.com/christophetd/CloudFlair.git
#	cd archive/CloudFlair
#	python3 -m venv venv
#	source venv/bin/activate
#	#pip install -r requirements.txt
#	#export CENSYS_API_ID=1ec2eadb-6bbe-485f-912f-32cdf106761f
#	#export CENSYS_API_SECRET=RbU5UbN7Er2XXZwSViHeBWAJ9DRxBP49
#	python cloudflair.py https://$domain 
#	deactivate	
#	
#	
#	echo "##########################"
#	echo "	EmailHarvester		"
#	echo "##########################"
#	cd $CAMINHO/tools/
#	cd Emailharvester
#	emailharvester -d $domain --user-agent "ByPass_$random" > temp_$domain.txt
#	cat temp_$domain.txt | grep "@" > email_$domain.txt
#
#	
#	echo "##########################"
#	echo "	Go-Dork			"
#	echo "##########################"
#	cd $CAMINHO/tools/Go-Dork/output/
#	for i in $(cat compromised_users.txt);do ./go-dork_1.0.3_linux_amd64 -q "allintext:$i" > $i.txt; done;
#
#
#	echo "##########################"
#	echo "	H8mail			"
#	echo "##########################"
#	h8mail -t $CAMINHO/tools/Emailharvester/email_$domain.txt 
#
#
#	echo "##########################"
#	echo "	Enumrepo				"
#	echo "##########################"
#
#	echo "##########################"
#	echo "	Pagodo					"
#	echo "##########################"
##cd $CAMINHO/tools/pagodo/	#python pagodo.py -d $domain -g dorks/error_messages.dorks -l --proxies ../yagooglesearch/proxy2.py --verbosity 3 --verbosity 1 > pagodo_error_messages_$domain.txt
##python pagodo.py -d $domain -g dorks/files_containing_usernames.dorks -l --proxies ../yagooglesearch/proxy2.py --verbosity 3 --verbosity 1 > pagodo_files_containing_usernames_$domain.txt
##python pagodo.py -d $domain -g dorks/vulnerable_files.dorks -l --proxies ../yagooglesearch/proxy2.py --verbosity 3 --verbosity 1 > pagodo_vulnerable_files_$domain.txt
##python pagodo.py -d $domain -g dorks/vulnerable_servers.dorks -l --proxies ../yagooglesearch/proxy2.py --verbosity 3 --verbosity 1 > pagodo_vulnerable_servers_$domain.txt
##python pagodo.py -d $domain -g dorks/web_server_detection.dorks -l --proxies ../yagooglesearch/proxy2.py --verbosity 3 --verbosity 1 > pagodo_web_server_detection_dorks_$domain.txt
##python pagodo.py -d $domain -g dorks/sensitive_directories.dorks -l --proxies ../yagooglesearch/proxy2.py --verbosity 3 --verbosity 1 > pagodo_sensitive_directories_$domain.txt#__End__
fi




