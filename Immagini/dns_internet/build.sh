#!/bin/bash

docker build -t dns_internet .

docker run --privileged -t dns_internet

