#!/bin/bash

docker build -t host_int1 .

docker run --privileged -t host_int1

