# Dockerfile: host della rete internet esterna


FROM ubuntu:latest


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
  
CMD echo "Host in rete pubblica - host_internet" 


 
