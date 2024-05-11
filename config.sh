#/bin/bash

# HTTPX, Aquatone, Gau, Gf, Dirsearch, SecretFinder, CloudFlair, EmailHarvester, Go-Dork, 
# H8mail, Pagodo, Sudomy, Ctrf, Sublist3r, MetaFinder
# Whatweb, lbd, Wafw00f, nmap, Wpscan, Nikto, DNSRecon

# Categories
#
# Waf Detection {CloudFlair, Wafw00f, Imperva-detect}
# Email {EmailHarvester, H8mail}
# Subdomain Discovery {Sudomy, Ctrf, Sublist3r}
# Google Dorks {Pagodo, Go-Dork, }
# OSINT {Recon-NG, }
# Check Ciphers {Check_ciphers, }
# DNS Check {DNSrecon}
# Metadata {MetaFinder, }
# Vulnerability Scanner {Nuclei, Nmap, }
# SSRF {Gopherus}

#
#export CAMINHO="/home/kali"
#echo "PATH: "$CAMINHO
#
#if [ -f Pentest ]; then
#   echo "[+] Existe a pasta Pentest"
#else
#	mkdir Pentest
#fi
#
# Install Dependecies
#echo "[+] Instalando dependencias"
#
#apt-get install python3 -y
#apt-get install golang -y
#apt-get install jq -y
#pip install yagooglesearch
#
#google="google-chrome"
#cd /opt/google/chrome/
#
#if [ -f $google ]; then
#   echo "[+] Existe google-chrome"
#else
#   echo "[-] Nao existe google-chrome"
#   cd $CAMINHO/archives/
#   dpkg -i google-chrome-stable_current_amd64.deb
#
#   # Remove google-chrome
#   rm -rf google-chrome-stable_current_amd64.deb
#fi
#
## Installing dafault Tools
#apt-get install whatweb -y
#apt-get install lbd -y
#apt-get install wafw00f -y
#apt-get install nmap -y
#apt-get install wpscan -y
#apt-get install nikto -y
#apt-get install dnsrecon -y
#pip3 install metafinder --upgrade
#sudo apt-get install p7zip-full
####

cd archives/

# Install Sudomy
#echo "[+] Instalando Sudomy"
#unzip Sudomy-master.zip
#rm -rf Sudomy-master.zip
#mv Sudomy-master Sudomy 
#
## Install ctfr
#echo "[+] Instalando Ctfr"
#unzip ctfr-master.zip
#rm -rf ctfr-master.zip
#mv ctfr-master ctfr
#
## Install Sublist3r
#echo "[+] Instalando Sublist3r"
#unzip Sublist3r-master.zip
#rm -rf Sublist3r-master.zip
#mv Sublist3r-master Sublist3r
#
## Install Httpx
#echo "[+] Instalando Httpx"
#unzip httpx-main.zip
#rm -rf httpx-main.zip
#mv httpx-main httpx
#cd httpx/cmd/httpx 
#go build httpx.go
#mv httpx ../../
#cd ../../../ 

# Install gau
#echo "[+] Instalando Gau"
#unzip gau-master.zip
#rm gau-master.zip
#cd gau-master/cmd/gau/
#go build main.go
#mv main gau
#mv gau ../../
#cd ..

# Install Gf
#echo "[+] Instalando Gf"
#unzip gf-master.zip
#rm gf-master.zip
#cd gf-master
#go build main.go
#mv main gf
#cp gf /usr/bin
#mkdir /root/.gf/
#cd examples	
#cp * /root/.gf/
#cd ../../
#mv gf-master gf

# Config. Gf
#unzip Gf-Patterns-master.zip
#rm -rf Gf-Patterns-master.zip
#mv Gf-Patterns-master Gf-Patterns 
#cd Gf-Patterns
#cp * /root/.gf/
#cd ..

# Install Aquatone
echo "[+] Instalando Aquatone"
unzip aquatone-master.zip
rm aquatone-master.zip
cd ..

## Install Dirsearch
#echo "[+] Instalando Dirsearch"
#unzip dirsearch-master.zip
#rm -rf dirsearch-master.zip
#
## Copy Gau to bin 
#cd gau/
#cp gau /usr/bin
#cd ..
#
## Install SecretFinder
#echo "[+] Instalando SecretFinder"
#unzip SecretFinder-master.zip
#rm -rf SecretFinder-master.zip
#
## Install yagooglesearch
#echo "[+] Instalando Yagooglesearch"
#unzip yagooglesearch-master.zip
#rm -rf yagooglesearch-master.zip
#cd yagooglesearch
#virtualenv -p python3 .venv  # If using a virtual environment.
#source .venv/bin/activate  # If using a virtual environment.
#pip install .  # Reads from pyproject.toml
#source desactivate
#cd ..
#
## Install Pagodo
#echo "[+] Instalando Pagodo"
#tar xvzf pagodo-2.6.2.tar.gz
#mv pagodo-2.6.2 pagodo  
#rm -rf pagodo-2.6.2.tar.gz
#
## Install EmailHarvester
#echo "[+] Instalando EmailHarvester"
#mkdir Emailharvester
#apt-get install emailharvester -y
#
## Install Go-Dork
#echo "[+] Instalando Go-Dork"
#mkdir go-dork
#mv go-dork_1.0.3_linux_amd64 go-dork
#cd go-dork
#chmod u+x go-dork_1.0.3_linux_amd64
#mkdir output
#cd ..
#
## Install CloudFlair
#echo "[+] Instalando CloudFlair"
#unzip CloudFlair-master.zip
#rm -rf CloudFlair-master.zip
#
## Install H8mail
#echo "[+] Instalando H8mail"
#unzip h8mail-2.5.6.zip
#rm -rf h8mail-2.5.6.zip
#cd h8mail-2.5.6
#make install
#cd ..
#
## Install LinkFinder
#echo "[+] Instalando LinkFinder"
#unzip LinkFinder-master.zip
#rm -rf LinkFinder-master.zip
#
## Install MetaFinder
#unzip LinkFinder-master.zip
#rm -rf LinkFinder-master.zip
#
## Install Imperva-detect
#unzip imperva-detect-master.zip
#rm -rf imperva-detect-master.zip
#cd imperva-detect-master
#chmod +x check_ciphers.sh
#chmod +x imperva-detect.sh
#

