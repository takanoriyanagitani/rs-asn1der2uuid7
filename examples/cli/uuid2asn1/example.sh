#!/bin/sh

der2fq(){
	cat /dev/stdin |
		fq -d asn1_ber
}

der2jer(){
	cat /dev/stdin |
		xxd -ps |
		tr -d '\n' |
		python3 -m asn1tools \
			convert \
			-i der \
			-o jer \
			./uuid-v7.asn1 \
			RawUuidV7 \
			-
}

wazero run ./uuid2asn1.wasm |
	der2jer
