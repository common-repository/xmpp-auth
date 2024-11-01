#!/bin/sh

# This script will format your certificates.

for cert in ./*.pem
do
	ln -fs "$cert" `openssl x509 -hash -noout -in "$cert"`.0
done;

