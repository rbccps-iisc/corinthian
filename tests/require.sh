#!/bin/bash

sudo apt update
#sudo apt upgrade
#curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
#sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" -y
#sudo apt-get update -y
#sudo apt-get install docker-ce -y
sudo usermod -aG docker $USER

sudo apt-get -y update 
sudo apt-get install -y software-properties-common
sudo apt-get install -y apt-transport-https  ca-certificates curl software-properties-common
sudo apt-get install openssl ca-certificates
sudo apt-get install libffi-dev
#sudo python -m pip install -U requests[security]
#sudo apt install python python-pip libssl-dev 
#sudo pip install -U pyopenssl
#sudo pip install --upgrade cryptography
python -m pip3 install requests
python -m pip3 install urllib3
#python -m pip install pyasn1 
#python -m pip install ndg-httpsclient 
