#
# Dockerfile: dns della dmz
#

FROM ubuntu:latest
LABEL maintainer ariccitiello "al.riccitiello@studenti.unina.it"

RUN apt-get update && apt-get install -y \
  bridge-utils \
  net-tools \
  iputils-ping \
  nmap \
  traceroute \
  telnet \
  nano \
  tcpdump \
  bind9
    
CMD echo "Server DNS - Rete DMZ" 


 
