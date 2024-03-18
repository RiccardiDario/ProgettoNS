#!/bin/bash

docker build -t dns_dmz .

docker run --privileged -t dns_dmz

