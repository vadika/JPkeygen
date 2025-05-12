all: 
	bash ./keygen.sh

clean:
	rm -rf *.key *.pem *.xml *.hash *.pubkey  -rf uefi_keys bootloader
