# Dockerfile: webserver

FROM ubuntu:latest

RUN apt-get update && apt-get install -y \
  bridge-utils \
  net-tools \
  iputils-ping \
  nmap \
  traceroute \
  telnet \
  dnsutils \
  tcpdump \
  nano
  
RUN ln -snf /usr/share/zoneinfo/$CONTAINER_TIMEZONE /etc/localtime && echo $CONTAINER_TIMEZONE > /etc/timezone
RUN apt-get update && apt-get install -y tzdata  

RUN apt-get update && apt-get install -y \
    apache2


CMD echo "Webserver Apachi2"

 
