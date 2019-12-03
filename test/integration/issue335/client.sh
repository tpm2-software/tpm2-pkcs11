#!/bin/bash

openssl s_client -engine pkcs11 -keyform engine -key "pkcs11:model=Intel;manufacturer=Intel;serial=0000000000000000;token=label;id=%62%35%64%61%33%38%63%31%39%35%37%33%61%31%37%63;object=1;type=private" -CAfile ca.pem -cert client_tpm.pem 127.0.0.1


