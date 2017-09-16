#!/bin/bash
gcc -Wall -c tracking.c -fPIC && ld -Bshareable -o tracking.so tracking.o -lc &&
gcc -Wall -c unix.c -fPIC && ld -Bshareable -o unix.so unix.o -lc &&
gcc -Wall -c bugcheck.c -fPIC && ld -Bshareable -o bugcheck.so bugcheck.o -lc
