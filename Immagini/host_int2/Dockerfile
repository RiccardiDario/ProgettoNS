#
# Dockerfile: host 2 della rete interna
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
  dnsutils \
  nano \
  tcpdump \
  httpie
    
CMD echo "Host in rete interna - host_int2" 


 
