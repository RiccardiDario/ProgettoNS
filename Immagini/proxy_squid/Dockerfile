#
# Dockerfile: proxy_squid
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
  tcpdump \
  nano 

RUN ln -snf /usr/share/zoneinfo/$CONTAINER_TIMEZONE /etc/localtime && echo $CONTAINER_TIMEZONE > /etc/timezone
RUN apt-get update && apt-get install -y tzdata  

RUN apt-get update && apt-get install -y \
    squid

COPY squid.conf . /etc/squid/ 

CMD echo "Proxy proxy_squid"

 
