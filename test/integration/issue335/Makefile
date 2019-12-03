OPENSSL=openssl
PASSWORD_CA=whatever

#PKCS11_KEY="pkcs11:model=Intel;manufacturer=Intel;serial=0000000000000000;token=label;id=%64%64%32%63%35%61%34%32%66%64%62%36%32%66%63%31;object=1;type=public"


.PHONY: clean all check_env

all: client_tpm.pem

clean:
	@echo "$$(head -n1 index.txt)" > index.txt
	@echo 02 > serial
	@rm -f client.csr client.crt client_tpm.pem 02.pem

check_env:
	@echo Checking env...
ifndef PKCS11_KEY
	$(error PKCS11_KEY not defined)
endif

client.csr: check_env
	$(OPENSSL) req -new -engine pkcs11 -keyform engine -key "$(PKCS11_KEY)" -out client.csr -subj "/C=FR/ST=Radius/L=Somewhere/O=Example Inc./CN=testing/emailAddress=testing@123.com"

client.crt: client.csr ca.pem ca.key
	$(OPENSSL) ca -batch -keyfile ca.key -cert ca.pem -in client.csr  -key $(PASSWORD_CA) -out client.crt -extensions xpclient_ext -extfile xpextensions -config ./client.cnf

client_tpm.pem: client.crt
	$(OPENSSL) x509 -in client.crt -out client_tpm.pem -outform pem

