#!/bin/sh

python3 \
	-c 'import asn1tools; loc = asn1tools.compile_files("./uuid-v7.asn1")'
