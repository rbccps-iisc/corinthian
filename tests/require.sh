#!/bin/bash

sudo apt update
#sudo apt upgrade
#curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
#sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" -y
#sudo apt-get update -y
#sudo apt-get install docker-ce -y
sudo usermod -aG docker $USER

#sudo apt install python python-pip libssl-dev 
#sudo pip install -U pyopenssl
#sudo pip install --upgrade cryptography
pythom -m pip install requests
pythom -m pip install urllib3
#python -m pip install pyasn1 
#python -m pip install ndg-httpsclient 
