#/bin/bash

# Created by Vinicius Clemente
# Automation script pentest tools

echo "##########################################"
echo "	WELLCOME - CLEQUILL TOOL		"
echo "##########################################"


cd /home/kali/Desktop
mkdir pentest

export CAMINHO="/home/kali/Desktop/pentest"
echo "PATH: "$CAMINHO

# Install Dependecies
apt-get install python3 -y
apt-get install golang -y

google="google-chrome"
cd /opt/google/chrome/

if [ -f $google ]; then
   echo "[+] Existe google-chrome"
else
   echo "[-] Nao existe google-chrome"
   cd /home/kali/Download/
   wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
   dpkg -i google-chrome-stable_current_amd64.deb
fi

cd $CAMINHO

# Verifica as tools
tools=$CAMINHO/tools

if [ -d $tools ]; then
	echo "[+] Diretorio de ferramentas existe"
else  
	mkdir tools
	cd tools

	# Install Sudomy
     	echo "[-] Diretorio de ferramentas nao existe"
	
	echo "##########################"
   	echo "	Download Sudomy		"
	echo "##########################"
   	git clone https://github.com/screetsec/Sudomy.git
   	cd Sudomy
  
	echo "[+] Instaling dependences Sudomy"
   	pip3 install -r requirements.txt
   	apt-get install jq -y
   	cd ..

   	# Install ctfr
  	echo "##########################"
   	echo "	Download ctfr		"
	echo "##########################"
   	git clone https://github.com/UnaPibaGeek/ctfr.git
   	cd ctfr
   	echo "[+] Installing dependeces ctfr"
   	pip3 install -r requirements.txt
  	cd ..

   	# Install Sublist3r
  	echo "##########################"
   	echo "	Download Sublist3r	"
	echo "##########################"
   	git clone https://github.com/aboul3la/Sublist3r.git
   	cd Sublist3r
   	echo "[+] Installing dependeces Sublist3r"
   	pip3 install -r requirements.txt
     	cd ..
  
	# Install Httpx
	echo "##########################"
     	echo "	Download Httpx		"
	echo "##########################"
	mkdir httpx
	wget https://github.com/projectdiscovery/httpx/releases/download/v1.6.0/httpx_1.6.0_linux_amd64.zip
	mv httpx_1.6.0_linux_amd64.zip httpx/
	cd httpx 
	unzip httpx_1.6.0_linux_amd64.zip
	cd ..
	
	# Install gau
	echo "##########################"
	echo "	Download Gau		"
	echo "##########################"
	mkdir gau
	cd gau
	wget https://github.com/lc/gau/releases/download/v2.2.1/gau_2.2.1_linux_amd64.tar.gz
	tar xvf gau_2.2.1_linux_amd64.tar.gz
	rm gau_2.2.1_linux_amd64.tar.gz
	cd ..

	echo "##########################"
	echo "	Download gf		"
	echo "##########################"
	git clone https://github.com/tomnomnom/gf.git
	cd gf
	go build main.go
	mv main gf
	cp gf /usr/bin
	mkdir /root/.gf/
	cd examples	
	cp * /root/.gf/
	cd ..

	git clone https://github.com/1ndianl33t/Gf-Patterns.git
	cd Gf-Patterns
	cp * /root/.gf/
	cd ..
	cd ..

	echo "##########################"
	echo "	Download Aquatone	"
	echo "##########################"
	mkdir aquatone
	cd aquatone
	wget https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_amd64_1.7.0.zip
	unzip aquatone_linux_amd64_1.7.0.zip
	cd ..

	# Install Dirsearch
	echo "##########################"
	echo "	Download Dirsearch	"
	echo "##########################"
	git clone https://github.com/maurosoria/dirsearch.git --depth 1
   	cd dirsearch
	echo "[+] Installing dependeces Dirsearch"
	pip install -r requirements.txt
	cd ..


	# Copy Gau to bin 
   	cd gau/
	cp gau /usr/bin
	cd ..

	echo "##########################"
	echo "	 Download SecretFinder	"
	echo "##########################"
	git clone https://github.com/m4ll0k/SecretFinder.git
	cd SecretFinder
	pip install -r requirements.txt
	cd ..

	rm -rf google-chrome-stable_current_amd64.deb


	# Install yagooglesearch
	pip install yagooglesearch
	git clone https://github.com/opsdisk/yagooglesearch
	cd yagooglesearch
	virtualenv -p python3 .venv  # If using a virtual environment.
	source .venv/bin/activate  # If using a virtual environment.
	pip install .  # Reads from pyproject.toml
	wget https://github.com/ViniciusClement/Proxies/blob/main/proxy.py
	cd ..


	# Install Pagodo
	echo "##########################"
	echo "	Download Pagodo		"
	echo "##########################"
	wget https://github.com/opsdisk/pagodo/archive/refs/tags/v2.6.2.tar.gz
	tar xvzf v2.6.2.tar.gz
	mv pagodo-2.6.2 pagodo  
	cd pagodo
	pip install -r requirements.txt
	cd ..
	
	# Install EmailHarvester
	echo "##########################"
	echo "	Download EmailHarvester	"
	echo "##########################"
	apt-get install emailharvester -y
	mkdir Emailharvester
   

	# Install Go-Dork
	echo "##########################"
	echo "	Download GoDork		"
	echo "##########################"
	mkdir Go-Dork
	cd Go-Dork
	wget https://github.com/dwisiswant0/go-dork/releases/download/v1.0.3/go-dork_1.0.3_linux_amd64
	chmod u+x go-dork_1.0.3_linux_amd64
 	mkdir output

	
	echo "##########################"
	echo "	Download Cloudflair	"
	echo "##########################"
        cd $CAMINHO/tools
	mkdir CloudFlair
	cd CloudFlair
	git clone https://github.com/christophetd/CloudFlair.git
	

	echo "##########################"
	echo "	Download H8mail		"
	echo "##########################"
	cd $CAMINHO/tools/
	wget https://github.com/khast3x/h8mail/archive/refs/tags/2.5.6.zip
 	unzip 2.5.6.zip
	cd h8mail-2.5.6
	make install


fi

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

# Option 1
if [ "$option" -eq 1 ]; then
    	echo -n "[1] - Subdomain: "
    	read domain
    
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
	echo "Execute tool Sudomy, Sublist3r, Ctrf"
	
	cd tools/

	# Run tools
	# Sudomy
	cd Sudomy/
	echo "##########################"
	echo "	Running Sudomy		"
	echo "##########################"
	./sudomy -d $domain -o sudomy_$domain
	cd sudomy_$domain/Sudomy-Output/$domain/
	mv subdomain.txt ../../../../../$domain/output/
	echo "[+] Copy file"

	cd ../../../../

	#Run ctfr
	cd ctfr/
	echo "##########################"
	echo "	Running ctfr		"
	echo "##########################"
	python3 ctfr.py -d $domain -o ctfr_$domain.txt
	mv ctfr_$domain.txt ../../$domain/output/
	echo "[+] Copy file"
	cd ..

	# Run Sublist3r
	cd Sublist3r
	echo "##########################"
	echo "	Running Sublist3r	"
	echo "##########################"
	python3 sublist3r.py -d $domain -o sublister_$domain.txt
	mv sublister_$domain.txt ../../$domain/output/
	echo "[+] Copy file"
	cd ..

	# Parse output
	echo "##########################"
	echo "	Parsing output files	"
       	echo "##########################"	
	cd ..
	cd $domain
	cd output
	
	cat sublister_$domain.txt | sort | uniq >> tmp_all_$domain.txt
	cat ctfr_$domain.txt | sort | uniq >> tmp_all_$domain.txt
	cat subdomain.txt | sort | uniq >> tmp_all_$domain.txt
	mv tmp_all_$domain.txt all_$domain.txt

	# Run HTTPX
	echo "##########################"
	echo "	Running HTTPX		"
	echo "##########################"
	cd $CAMINHO
	cd tools/httpx
	./httpx -l ../../$domain/output/all_$domain.txt  -sc -timeout 15 -cdn -o sc_live_$domain.txt
	mv sc_live_$domain.txt ../../$domain/output/
	./httpx -l ../../$domain/output/all_$domain.txt -timeout 15 -o live_$domain.txt
	mv live_$domain.txt ../../$domain/output

	# Remove Temp files
	cd $CAMINHO
	cd $domain/output

	rm sublister_$domain.txt
	rm ctfr_$domain.txt
	rm subdomain.txt

	# Run aquatone
	echo "##########################"
	echo "	Running Aquatone	"
	echo "##########################"
	cat live_$domain.txt | aquatone -chrome-path /opt/google/chrome/google-chrome


	# Run Gau
	echo "##########################"
	echo "	Running Gau		"
	echo "##########################"
	cat live_$domain.txt | gau --verbose --threads 10 > gau_$domain.txt

	
	# Run Gf
	mkdir gf

	echo "##########################"
	echo "	Running Gf		"
	echo "##########################"
	cat gau_$domain.txt | gf xss > gf/xss_$domain.txt
	cat gau_$domain.txt | gf sqli > gf/sqli_$domain.txt
	cat gau_$domain.txt | gf lfi > gf/lfi_$domain.txt
	cat gau_$domain.txt | gf http-auth > gf/http-auth_$domain.txt
	cat gau_$domain.txt | gf idor > gf/idor_$domain.txt
	cat gau_$domain.txt | gf img-traversal > gf/img-traversal.$domain.txt
	cat gau_$domain.txt | gf interestingEXT > gd/interestingEXT_$domain.txt
	cat gau_$domain.txt | gf interestingparams > gf/interestingparams_$domain.txt
	cat gau_$domain.txt | gf interestingsubs > gf/interestingsubs_$domain.txt
	cat gau_$domain.txt | gf php-errors > gf/php-errors_$domain.txt
	cat gau_$domain.txt | gf php-serialized > gf/php-serialized_$domain.txt
	cat gau_$domain.txt | gf rce > gf/rce_$domain.txt
	cat gau_$domain.txt | gf redirect > gf/redirect_$domain.txt
	cat gau_$domain.txt | gf s3-buckets > gf/s3-buckets_$domain.txt
	cat gau_$domain.txt | gf sec > gf/sec_$domain.txt
	cat gau_$domain.txt | gf ssrf > gf/ssrf_$domain.txt
	cat gau_$domain.txt | gf ssti > gf/ssti_$domain.txt

# Option 2
else
    	echo -n "[2] - Enter Domain: "
    	read domain
	

	# Conf. env
    	cd $CAMINHO

    	# Verify Directory
    	filename='$domain'

    	if [ -d $filename ]; then
        	echo '[+] Existe este diretorio $domain'
    	else
        	echo "##########################"
        	echo "	Created '$domain'	"
		echo "##########################"
        	mkdir $domain
        	ls -lt | grep $domain
		cd $domain
		mkdir output
		cd ..
   	fi

	# Execute tools
	
	# Run HTTPX
        echo "##########################"
        echo "	Running HTTPX		"
	echo "##########################"
        cd $CAMINHO/tools/httpx/
        ./httpx -u $domain -timeout 15 -o live_$domain.txt
        mv live_$domain.txt ../../$domain/output

        cd $CAMINHO
        cd $domain/output

        # Run aquatone
	echo "##########################"
        echo "	Running Aquatone	"
	echo "##########################"
	cat live_$domain.txt | aquatone -chrome-path /opt/google/chrome/google-chrome

	echo "##########################"
	echo "	Running Gau		"
	echo "##########################"
        cat live_$domain.txt | gau --verbose --threads 10 > gau_$domain.txt

        mkdir gf
	echo "##########################"
	echo "	Running Gf		"
	echo "##########################"
        cat gau_$domain.txt | gf xss > gf/xss_$domain.txt
        cat gau_$domain.txt | gf sqli > gf/sqli_$domain.txt
        cat gau_$domain.txt | gf lfi > gf/lfi_$domain.txt
        cat gau_$domain.txt | gf http-auth > gf/http-auth_$domain.txt
        cat gau_$domain.txt | gf idor > gf/idor_$domain.txt
        cat gau_$domain.txt | gf img-traversal > gf/img-traversal.$domain.txt
        cat gau_$domain.txt | gf interestingEXT > gf/interestingEXT_$domain.txt
        cat gau_$domain.txt | gf interestingparams > gf/interestingparams_$domain.txt
        cat gau_$domain.txt | gf interestingsubs > gf/interestingsubs_$domain.txt
        cat gau_$domain.txt | gf php-errors > gf/php-errors_$domain.txt
        cat gau_$domain.txt | gf php-serialized > gf/php-serialized_$domain.txt
        cat gau_$domain.txt | gf rce > gf/rce_$domain.txt
        cat gau_$domain.txt | gf redirect > gf/redirect_$domain.txt
        cat gau_$domain.txt | gf s3-buckets > gf/s3-buckets_$domain.txt
        cat gau_$domain.txt | gf sec > gf/sec_$domain.txt
        cat gau_$domain.txt | gf ssrf > gf/ssrf_$domain.txt
        cat gau_$domain.txt | gf ssti > gf/ssti_$domain.txt

	random=date | awk '{print $4}'

	echo "##########################"
	echo "	Running Whatweb		"
	echo "##########################"
	whatweb $domain --colour=always --user-agent="Bypass_$random" --aggression=3 -v --log-verbose=whatweb_verbose.txt

	echo "##########################"
	echo "	Running lbd		"
	echo "##########################"
	lbd $domain 
	lbd $domain > lbd_$domain.txt

	echo "##########################"
	echo "	Running Wafw00f		"
	echo "##########################"
	#wafw00f $domain 
	wafw00f $domain > wafw00f_$domain.txt

	#resposta=$(cat wafw00f_$domain.txt | grep "No WAF detected by the generic detection")

	#if [ $resposta == "No WAF detected by the generic detection" ]; then
	#	echo "No WAF detected"
	host $domain | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" > ips_$domain.txt
	echo "##########################"
	echo "	Running NMAP		"
	echo "##########################"
	nmap -iL ips_$domain.txt -sV -D RND 20 -f --script=vuln -oN nmap_$domain.txt
	#else
	#	echo "WAF Detected"
	#fi

	echo "##########################"
	echo "	Running WPScan		"
	echo "##########################"
	#wpscan --update
	wpscan --url https://$domain -e at --random-user-agent --api-token LUj8CFzb3m3YffuwsKM1QFoNb5hU2PQOypc8q5V8Xhw  --stealthy  --ignore-main-redirect

	echo "##########################"
	echo "	Running Nikto		"
	echo "##########################"
	nikto -host $domain -useragent="Bypass" 

	echo "##########################"
	echo "	Running DNSrecon	"
	echo "##########################"
	dnsrecon -a -d $domain -v
	dnsrecon -a -d $domain -v > dnsrecon_$domain.txt
	
	echo "##########################"
	echo "	Running Dirsearch	"
	echo "##########################"
	cd $CAMINHO/tools/dirsearch
	#pip install -r requirements.txt
	#python3 dirsearch.py -u https://$domain --crawl -o dirsearch_$domain.txt 
 

	echo "##########################"
	echo "	Running SecretFinder	"
	echo "##########################"
	cd $CAMINHO/tools/SecretFinder
	#pip install -r requirements.txt 
	#python3 SecretFinder.py -i https://$domain -e -o $domain.html
	

	echo "##########################"
	echo "	CloudFlair		"
	echo "##########################"
	cd $CAMINHO/tools/
	#git clone https://github.com/christophetd/CloudFlair.git
	cd CloudFlair
	python3 -m venv venv
	source venv/bin/activate
	pip install -r requirements.txt
	export CENSYS_API_ID=1ec2eadb-6bbe-485f-912f-32cdf106761f
	export CENSYS_API_SECRET=RbU5UbN7Er2XXZwSViHeBWAJ9DRxBP49
	python cloudflair.py https://$domain 
	source deactivate	
	
	
	echo "##########################"
	echo "	EmailHarvester		"
	echo "##########################"
	cd $CAMINHO/tools/
	cd Emailharvester
	emailharvester -d $domain --user-agent "ByPass_$random" > temp_$domain.txt
	cat temp_$domain.txt | grep "@" > email_$domain.txt

	
	echo "##########################"
	echo "	Go-Dork			"
	echo "##########################"
	cd $CAMINHO/tools/Go-Dork/output/
	for i in $(cat compromised_users.txt);do ./go-dork_1.0.3_linux_amd64 -q "allintext:$i" > $i.txt; done;


	echo "##########################"
	echo "	H8mail			"
	echo "##########################"
	h8mail -t $CAMINHO/tools/Emailharvester/email_$domain.txt 


	echo "##########################"
	echo "	Pagodo			"
	echo "##########################"
	#cd $CAMINHO/tools/pagodo/
	#python pagodo.py -d $domain -g dorks/error_messages.dorks -l --proxies ../yagooglesearch/proxy2.py --verbosity 3 --verbosity 1 > pagodo_error_messages_$domain.txt

	#python pagodo.py -d $domain -g dorks/files_containing_usernames.dorks -l --proxies ../yagooglesearch/proxy2.py --verbosity 3 --verbosity 1 > pagodo_files_containing_usernames_$domain.txt

	#python pagodo.py -d $domain -g dorks/vulnerable_files.dorks -l --proxies ../yagooglesearch/proxy2.py --verbosity 3 --verbosity 1 > pagodo_vulnerable_files_$domain.txt

	#python pagodo.py -d $domain -g dorks/vulnerable_servers.dorks -l --proxies ../yagooglesearch/proxy2.py --verbosity 3 --verbosity 1 > pagodo_vulnerable_servers_$domain.txt

	#python pagodo.py -d $domain -g dorks/web_server_detection.dorks -l --proxies ../yagooglesearch/proxy2.py --verbosity 3 --verbosity 1 > pagodo_web_server_detection_dorks_$domain.txt

	#python pagodo.py -d $domain -g dorks/sensitive_directories.dorks -l --proxies ../yagooglesearch/proxy2.py --verbosity 3 --verbosity 1 > pagodo_sensitive_directories_$domain.txt

#__End__
fi

