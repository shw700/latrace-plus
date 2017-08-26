#!/bin/bash
gcc -Wall -c tracking.c -fPIC && ld -Bshareable -o tracking.so tracking.o -lc
