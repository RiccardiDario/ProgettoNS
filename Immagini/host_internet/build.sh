#!/bin/bash

docker build -t host_internet .

docker run --privileged -t host_internet

