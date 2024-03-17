#!/bin/bash

docker build -t host_int .

docker run --privileged -t host_int
