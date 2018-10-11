#!/bin/bash

sudo apt update
sudo apt upgrade
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" -y
sudo apt-get update -y
sudo apt-get install docker-ce -y
sudo usermod -aG docker $USER

#sudo apt update 
sudo apt remove curl
sudo apt install curl
#sudo apt-get upgrade 
#sudo apt-get install -y software-properties-common
#sudo apt-get install -y apt-transport-https  ca-certificates curl software-properties-common
#sudo apt-get install openssl ca-certificates
#sudo apt-get install libffi-dev
#sudo apt-get install python python3-pip
#sudo python3 -m pip install -U requests[security]
#sudo python3 -m pip install -U pyopenssl
#sudo python3 -m pip install --upgrade cryptography
#sudo python3 -m pip install requests
#sudo python3 -m pip install urllib3
#sudo python3 -m pip install pyasn1 
#sudo python3 -m pip install ndg-httpsclient 
