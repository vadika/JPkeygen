#!/bin/bash
# Script to generate security keys for NVIDIA Tegra platform using NetHSM appliance
# This generates RSA keys, SBK keys, KEK keys, and UEFI secure boot keys

# Exit immediately if a command exits with a non-zero status
set -e

# Activate Python virtual environment if it exists
if [ -d ".venv" ]; then
    echo "Activating Python virtual environment..."
    source .venv/bin/activate
fi

# Check for NetHSM configuration
if [ -z "$NETHSM_URL" ] || [ -z "$NETHSM_USERNAME" ] || [ -z "$NETHSM_PASSWORD" ]; then
    echo "NetHSM environment variables not set. Please set:"
    echo "  NETHSM_URL - URL of your NetHSM appliance"
    echo "  NETHSM_USERNAME - Username for NetHSM authentication"
    echo "  NETHSM_PASSWORD - Password for NetHSM authentication"
    exit 1
fi

# Initialize NetHSM connection
echo "Connecting to NetHSM appliance at $NETHSM_URL..."
nitrokey nethsm login --username "$NETHSM_USERNAME" --password "$NETHSM_PASSWORD" --url "$NETHSM_URL"
if [ $? -ne 0 ]; then
    echo "Failed to connect to NetHSM appliance. Please check your credentials and connection."
    exit 1
fi

# Check if keys already exist and warn user before proceeding
if [ -f "rsa.pem" ] || [ -f "sbk.key" ] || [ -f "kek.key" ] || [ -d "uefi_keys" ]; then
    echo "WARNING: Some key files already exist in the current directory."
    echo "Generating new keys will overwrite existing ones, otherwise run make clean."
    read -p "Do you want to continue? (y/n): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Key generation aborted."
        exit 1
    fi
fi

# Define paths to NVIDIA Tegra tools
TEGRASIGN="../JP/Linux_for_Tegra/bootloader/tegrasign_v3.py"  # Tool for signing and key operations
UEFIDTSGEN="../JP/Linux_for_Tegra/tools/gen_uefi_keys_dts.sh"  # Tool for generating UEFI keys device tree
GENEKB="../JP/Linux_for_Tegra/source/optee/samples/hwkey-agent/host/tool/gen_ekb/gen_ekb.py"  # Tool for generating OP-TEE encrypted key blob

# Generate RSA key pair (3072 bits) for secure boot using NetHSM
echo "Generating RSA key pair using NetHSM..."
RSA_KEY_ID="tegra-rsa-$(date +%s)"
nitrokey nethsm keys generate --id "$RSA_KEY_ID" --type RSA --bits 3072 --exportable-private-key
nitrokey nethsm keys export --id "$RSA_KEY_ID" --format PEM > rsa.pem

# Generate public key hash in tegra-fuse format for burning into fuses
PKCS_KEY_XML_HASH=$($TEGRASIGN --pubkeyhash rsa.pubkey rsa.hash --key rsa.pem | grep "tegra-fuse format" | awk '{print $NF}')

# Generate Secure Boot Key (SBK) using NetHSM - 256-bit random key
echo "Generating Secure Boot Key using NetHSM..."
SBK_KEY_ID="tegra-sbk-$(date +%s)"
nitrokey nethsm keys generate --id "$SBK_KEY_ID" --type AES --bits 256 --exportable-private-key
SBK_RAW=$(nitrokey nethsm keys export --id "$SBK_KEY_ID" --format RAW | xxd -p -c 32)

# Format SBK key in space-separated format (for command line tools)
SBK_0=${SBK_RAW:0:8}
SBK_1=${SBK_RAW:8:8}
SBK_2=${SBK_RAW:16:8}
SBK_3=${SBK_RAW:24:8}
SBK_4=${SBK_RAW:32:8}
SBK_5=${SBK_RAW:40:8}
SBK_6=${SBK_RAW:48:8}
SBK_7=${SBK_RAW:56:8}

SBK_KEY=$(echo "0x${SBK_0} 0x${SBK_1} 0x${SBK_2} 0x${SBK_3} 0x${SBK_4} 0x${SBK_5} 0x${SBK_6} 0x${SBK_7}")
echo "${SBK_KEY}" > sbk.key

# Format SBK key in continuous format (for XML)
SBK_KEY_XML="0x${SBK_RAW}"
echo "${SBK_KEY_XML}" > sbk_xml.key

# Generate Key Encryption Key (KEK) using NetHSM - 256-bit random key
echo "Generating Key Encryption Key using NetHSM..."
KEK_KEY_ID="tegra-kek-$(date +%s)"
nitrokey nethsm keys generate --id "$KEK_KEY_ID" --type AES --bits 256 --exportable-private-key
KEK_RAW=$(nitrokey nethsm keys export --id "$KEK_KEY_ID" --format RAW | xxd -p -c 32)

# Format KEK in space-separated format (for command line tools)
KEK_2_0=${KEK_RAW:0:8}
KEK_2_1=${KEK_RAW:8:8}
KEK_2_2=${KEK_RAW:16:8}
KEK_2_3=${KEK_RAW:24:8}
KEK_2_4=${KEK_RAW:32:8}
KEK_2_5=${KEK_RAW:40:8}
KEK_2_6=${KEK_RAW:48:8}
KEK_2_7=${KEK_RAW:56:8}

KEK_2_KEY=$(echo "0x${KEK_2_0} 0x${KEK_2_1} 0x${KEK_2_2} 0x${KEK_2_3} 0x${KEK_2_4} 0x${KEK_2_5} 0x${KEK_2_6} 0x${KEK_2_7}")
echo "${KEK_2_KEY}" > kek.key

# Format KEK in continuous format with 0x prefix (for XML)
KEK_2_KEY_XML="0x${KEK_RAW}"
echo "${KEK_2_KEY_XML}" > kek_xml.key

# Format KEK in continuous format without 0x prefix (for OP-TEE)
KEK_2_KEY_OPTEE="${KEK_RAW}"
echo "${KEK_2_KEY_OPTEE}" > kek_optee.key

# Generate symmetric keys for T234 SoC using NetHSM
echo "Generating symmetric keys for T234 SoC using NetHSM..."
SYM_KEY_ID="tegra-sym-$(date +%s)"
nitrokey nethsm keys generate --id "$SYM_KEY_ID" --type AES --bits 256 --exportable-private-key
nitrokey nethsm keys export --id "$SYM_KEY_ID" --format RAW | xxd -p -c 32 > sym_t234.key

SYM2_KEY_ID="tegra-sym2-$(date +%s)"
nitrokey nethsm keys generate --id "$SYM2_KEY_ID" --type AES --bits 128 --exportable-private-key
nitrokey nethsm keys export --id "$SYM2_KEY_ID" --format RAW | xxd -p -c 16 > sym2_t234.key

AUTH_KEY_ID="tegra-auth-$(date +%s)"
nitrokey nethsm keys generate --id "$AUTH_KEY_ID" --type AES --bits 128 --exportable-private-key
nitrokey nethsm keys export --id "$AUTH_KEY_ID" --format RAW | xxd -p -c 16 > auth_t234.key

# Generate UEFI Secure Boot keys using NetHSM
echo "Generating UEFI Secure Boot keys using NetHSM..."
mkdir -p uefi_keys
cd uefi_keys
GUID=$(uuidgen)  # Generate a unique GUID for the EFI signature lists

# Generate PK (Platform Key) using NetHSM
PK_KEY_ID="uefi-pk-$(date +%s)"
nitrokey nethsm keys generate --id "$PK_KEY_ID" --type RSA --bits 2048 --exportable-private-key
nitrokey nethsm keys export --id "$PK_KEY_ID" --format PEM > PK.key
openssl req -new -x509 -sha256 -days 3650 -subj "/CN=my Platform Key/" -key PK.key -out PK.crt
cert-to-efi-sig-list -g "${GUID}" PK.crt PK.esl

# Generate KEK (Key Exchange Key) using NetHSM
KEK_UEFI_KEY_ID="uefi-kek-$(date +%s)"
nitrokey nethsm keys generate --id "$KEK_UEFI_KEY_ID" --type RSA --bits 2048 --exportable-private-key
nitrokey nethsm keys export --id "$KEK_UEFI_KEY_ID" --format PEM > KEK.key
openssl req -new -x509 -sha256 -days 3650 -subj "/CN=my Key Exchange Key/" -key KEK.key -out KEK.crt
cert-to-efi-sig-list -g "${GUID}" KEK.crt KEK.esl

# Generate db_1 (Signature Database key 1) using NetHSM
DB1_KEY_ID="uefi-db1-$(date +%s)"
nitrokey nethsm keys generate --id "$DB1_KEY_ID" --type RSA --bits 2048 --exportable-private-key
nitrokey nethsm keys export --id "$DB1_KEY_ID" --format PEM > db_1.key
openssl req -new -x509 -sha256 -days 3650 -subj "/CN=my Signature Database key/" -key db_1.key -out db_1.crt
cert-to-efi-sig-list -g "${GUID}" db_1.crt db_1.esl

# Generate db_2 (Signature Database key 2) using NetHSM
DB2_KEY_ID="uefi-db2-$(date +%s)"
nitrokey nethsm keys generate --id "$DB2_KEY_ID" --type RSA --bits 2048 --exportable-private-key
nitrokey nethsm keys export --id "$DB2_KEY_ID" --format PEM > db_2.key
openssl req -new -x509 -sha256 -days 3650 -subj "/CN=my another Signature Database key/" -key db_2.key -out db_2.crt
cert-to-efi-sig-list -g "${GUID}" db_2.crt db_2.esl

# Create UEFI keys configuration file
cat > "uefi_keys.conf" << EOF
UEFI_DB_1_KEY_FILE="db_1.key";  # UEFI payload signing key
UEFI_DB_1_CERT_FILE="db_1.crt"; # UEFI payload signing key certificate

UEFI_DEFAULT_PK_ESL="PK.esl"    # Platform Key EFI Signature List
UEFI_DEFAULT_KEK_ESL_0="KEK.esl" # Key Exchange Key EFI Signature List

UEFI_DEFAULT_DB_ESL_0="db_1.esl" # Signature Database Key 1 EFI Signature List
UEFI_DEFAULT_DB_ESL_1="db_2.esl" # Signature Database Key 2 EFI Signature List
EOF

cd ..
# Generate UEFI keys device tree source file using the configuration
sudo $UEFIDTSGEN uefi_keys/uefi_keys.conf

# Generate the OP-TEE encrypted key blob (EKB) image
echo "Generating OP-TEE encrypted key blob..."
mkdir -p bootloader
python3 $GENEKB  -chip t234 -oem_k1_key kek_optee.key -in_sym_key sym_t234.key \
                 -in_sym_key2 sym2_t234.key -in_auth_key auth_t234.key \
                 -out bootloader/eks_t234.img

# Generate fuse programming XML file
echo "Generating fuse programming XML file..."
echo "<genericfuse MagicId=\"0x45535546\" version=\"1.0.0\">" > fuse.xml
echo "  <fuse name=\"PublicKeyHash\" size=\"64\" value=\"${PKCS_KEY_XML_HASH}\"/>" >> fuse.xml  # RSA public key hash
echo "  <fuse name=\"SecureBootKey\" size=\"32\" value=\"${SBK_KEY_XML}\"/>" >> fuse.xml       # Secure Boot Key
echo "  <fuse name=\"OemK1\" size=\"32\" value=\"${KEK_2_KEY_XML}\"/>" >> fuse.xml             # OEM Key (KEK)
echo "  <fuse name=\"BootSecurityInfo\" size=\"4\" value=\"0x209\"/>" >> fuse.xml              # Boot security configuration
echo "  <fuse name=\"SecurityMode\" size=\"4\" value=\"0x1\"/>" >> fuse.xml                    # Security mode (1=secure)
echo "</genericfuse>" >> fuse.xml

# Create a key inventory file for reference
echo "Creating key inventory file..."
echo "NetHSM Key Inventory for Tegra Security Keys" > nethsm_key_inventory.txt
echo "Generated on: $(date)" >> nethsm_key_inventory.txt
echo "NetHSM URL: $NETHSM_URL" >> nethsm_key_inventory.txt
echo "----------------------------------------" >> nethsm_key_inventory.txt
echo "RSA Key ID: $RSA_KEY_ID" >> nethsm_key_inventory.txt
echo "SBK Key ID: $SBK_KEY_ID" >> nethsm_key_inventory.txt
echo "KEK Key ID: $KEK_KEY_ID" >> nethsm_key_inventory.txt
echo "SYM Key ID: $SYM_KEY_ID" >> nethsm_key_inventory.txt
echo "SYM2 Key ID: $SYM2_KEY_ID" >> nethsm_key_inventory.txt
echo "AUTH Key ID: $AUTH_KEY_ID" >> nethsm_key_inventory.txt
echo "UEFI PK Key ID: $PK_KEY_ID" >> nethsm_key_inventory.txt
echo "UEFI KEK Key ID: $KEK_UEFI_KEY_ID" >> nethsm_key_inventory.txt
echo "UEFI DB1 Key ID: $DB1_KEY_ID" >> nethsm_key_inventory.txt
echo "UEFI DB2 Key ID: $DB2_KEY_ID" >> nethsm_key_inventory.txt

echo "Key generation complete. All keys have been generated using NetHSM appliance."
echo "Key IDs are stored in nethsm_key_inventory.txt for reference."
