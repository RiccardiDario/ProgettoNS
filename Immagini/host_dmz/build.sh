#!/bin/bash

docker build -t host_dmz .

docker run --privileged -t host_dmz

