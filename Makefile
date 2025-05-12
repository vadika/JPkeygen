# Makefile for Tegra security key generation

.PHONY: all clean prep

# Default target: generate all security keys
all: 
	bash ./keygen.sh

# Prepare virtual environment and install dependencies
prep:
	@echo "Creating Python virtual environment..."
	python3 -m venv .venv
	@echo "Installing required Python packages..."
	.venv/bin/pip install --upgrade pip
	.venv/bin/pip install -r requirements.txt
	@echo "Virtual environment setup complete. Activate with 'source .venv/bin/activate'"

# Clean target: remove all generated files and directories
clean:
	rm -rf *.key *.pem *.xml *.hash *.pubkey  -rf uefi_keys bootloader
