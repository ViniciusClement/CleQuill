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


if [ -f Pentest ]; then
   echo "[+] Existe a pasta Pentest"
else
	mkdir Pentest
fi

# Install Dependecies
echo "[+] Instalando dependencias"

apt-get install python3 -y
apt-get install golang -y
apt-get install jq -y
pip install yagooglesearch

google="google-chrome"
cd /opt/google/chrome/

if [ -f $google ]; then
   echo "[+] Existe google-chrome"
else
   echo "[-] Nao existe google-chrome"
   cd $CAMINHO/archives/
   wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
   dpkg -i google-chrome-stable_current_amd64.deb
   # Remove google-chrome
   rm -rf google-chrome-stable_current_amd64.deb
fi

# Installing dafault Tools
apt-get install whatweb -y
apt-get install lbd -y
apt-get install wafw00f -y
apt-get install nmap -y
apt-get install wpscan -y
apt-get install nikto -y
apt-get install dnsrecon -y
apt-get install amass -y
pip3 install metafinder --upgrade
sudo apt-get install p7zip-full

cd $CAMINHO/archives/

# Install Sudomy
echo "[+] Instalando Sudomy"
unzip Sudomy-master.zip
rm -rf Sudomy-master.zip
mv Sudomy-master Sudomy 

# Install ctfr
echo "[+] Instalando Ctfr"
unzip ctfr-master.zip
rm -rf ctfr-master.zip
mv ctfr-master ctfr

# Install Sublist3r
echo "[+] Instalando Sublist3r"
unzip Sublist3r-master.zip
rm -rf Sublist3r-master.zip
mv Sublist3r-master Sublist3r

# Install Httpx
echo "[+] Instalando Httpx"
unzip httpx-main.zip
rm -rf httpx-main.zip
mv httpx-main httpx
cd httpx/cmd/httpx 
go build httpx.go
mv httpx ../../
cd ../../../ 

# Install gau
echo "[+] Instalando Gau"
unzip gau-master.zip
rm gau-master.zip
cd gau-master/cmd/gau/
go build main.go
mv main gau
mv gau ../../
cd ../../
cp gau /usr/bin
cd ..

# Install Gf
echo "[+] Instalando Gf"
unzip gf-master.zip
rm -rf gf-master.zip
cd gf-master
go build main.go
mv main gf
cp gf /usr/bin
mkdir /root/.gf/
cd examples	
cp * /root/.gf/
cd ../../
mv gf-master gf

# Config. Gf
unzip Gf-Patterns-master.zip
rm -rf Gf-Patterns-master.zip
mv Gf-Patterns-master Gf-Patterns 
cd Gf-Patterns
cp * /root/.gf/
cd ..

# Install Aquatone
echo "[+] Instalando Aquatone"
mkdir aquatone
cd aquatone
wget https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_amd64_1.7.0.zip
unzip aquatone_linux_amd64_1.7.0.zip
cp aquatone /usr/bin/
rm aquatone_linux_amd64_1.7.0.zip
cd ..

# Install Dirsearch
echo "[+] Instalando Dirsearch"
unzip dirsearch-master.zip
rm -rf dirsearch-master.zip
mv dirsearch-master dirsearch

# Install SecretFinder
echo "[+] Instalando SecretFinder"
unzip SecretFinder-master.zip
rm -rf SecretFinder-master.zip
mv SecretFinder-master SecretFinder 

# Install yagooglesearch
echo "[+] Instalando Yagooglesearch"
unzip yagooglesearch-master.zip
rm -rf yagooglesearch-master.zip
mv yagooglesearch-master yagooglesearch
cd yagooglesearch
virtualenv -p python3 .venv  # If using a virtual environment.
source .venv/bin/activate  # If using a virtual environment.
pip install .  # Reads from pyproject.toml
source desactivate
cd ..

# Install Pagodo
echo "[+] Instalando Pagodo"
unzip pagodo-master.zip
rm pagodo-master.zip
mv pagodo-master pagodo

# Install EmailHarvester
echo "[+] Instalando EmailHarvester"
mkdir Emailharvester
apt-get install emailharvester -y

## Install Go-Dork
echo "[+] Instalando Go-Dork"
unzip go-dork-master.zip
rm go-dork-master.zip
mv go-dork-master go-dork
cd go-dork
mkdir output
go build 
cd ..

# Install CloudFlair
echo "[+] Instalando CloudFlair"
unzip CloudFlair-master.zip
rm -rf CloudFlair-master.zip
mv CloudFlair-master CloudFlair
cd CloudFlair
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
export CENSYS_API_ID=1ec2eadb-6bbe-485f-912f-32cdf106761f
export CENSYS_API_SECRET=RbU5UbN7Er2XXZwSViHeBWAJ9DRxBP49
python cloudflair.py -h
source deactivate	
cd ..

# Install H8mail
echo "[+] Instalando H8mail"
unzip h8mail-master.zip
rm h8mail-master.zip
mv h8mail-master h8mail
cd h8mail
make install
cd ..

# Install MetaFinder
echo "[+] Instalando MetaFinder"
mkdir MetaFinder 
pip3 install metafinder --upgrade

# Install Imperva-detect
cd imperva-detect
chmod +x check_ciphers.sh
chmod +x imperva-detect.sh
cd ..

# Install Enumerepo
unzip enumerepo-main.zip
mv enumerepo-main enumerepo
rm enumerepo-main.zip
cd enumerepo
go build
cd ..


