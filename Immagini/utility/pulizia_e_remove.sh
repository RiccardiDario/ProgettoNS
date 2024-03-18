#!/bin/bash

#Pulizia
docker stop $(docker ps -a -q)
docker rm $(docker ps -a -q)
docker network rm rete_interna 
docker network rm dmz
docker network rm rete_didattica
docker network rm rete_esterna

docker image prune -a
