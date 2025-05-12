# Makefile for Tegra security key generation

# Default target: generate all security keys
all: 
	bash ./keygen.sh

# Clean target: remove all generated files and directories
clean:
	rm -rf *.key *.pem *.xml *.hash *.pubkey  -rf uefi_keys bootloader
