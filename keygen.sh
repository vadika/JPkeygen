#!/bin/bash
# Script to generate security keys for NVIDIA Tegra platform
# This generates RSA keys, SBK keys, KEK keys, and UEFI secure boot keys

# Exit immediately if a command exits with a non-zero status
set -e

# Activate Python virtual environment if it exists
if [ -d ".venv" ]; then
    echo "Activating Python virtual environment..."
    source .venv/bin/activate
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

# Generate RSA key pair (3072 bits) for secure boot
openssl genrsa -out rsa.pem 3072

# Generate public key hash in tegra-fuse format for burning into fuses
PKCS_KEY_XML_HASH=$($TEGRASIGN --pubkeyhash rsa.pubkey rsa.hash --key rsa.pem | grep "tegra-fuse format" | awk '{print $NF}')

# Generate Secure Boot Key (SBK) - 256-bit random key (8 x 32-bit words)
# SBK is used for encryption of boot components
SBK_0=$(openssl rand -hex 4)
SBK_1=$(openssl rand -hex 4)
SBK_2=$(openssl rand -hex 4)
SBK_3=$(openssl rand -hex 4)
SBK_4=$(openssl rand -hex 4)
SBK_5=$(openssl rand -hex 4)
SBK_6=$(openssl rand -hex 4)
SBK_7=$(openssl rand -hex 4)

# Format SBK key in space-separated format (for command line tools)
SBK_KEY=$(echo "0x${SBK_0} 0x${SBK_1} 0x${SBK_2} 0x${SBK_3} 0x${SBK_4} 0x${SBK_5} 0x${SBK_6} 0x${SBK_7}")
echo "${SBK_KEY}" > sbk.key

# Format SBK key in continuous format (for XML)
SBK_KEY_XML="0x${SBK_0}${SBK_1}${SBK_2}${SBK_3}${SBK_4}${SBK_5}${SBK_6}${SBK_7}"
echo "${SBK_KEY_XML}" > sbk_xml.key
# Generate Key Encryption Key (KEK) - 256-bit random key (8 x 32-bit words)
# KEK is used for encrypting other keys in the system
KEK_2_0=$(openssl rand -hex 4)
KEK_2_1=$(openssl rand -hex 4)
KEK_2_2=$(openssl rand -hex 4)
KEK_2_3=$(openssl rand -hex 4)
KEK_2_4=$(openssl rand -hex 4)
KEK_2_5=$(openssl rand -hex 4)
KEK_2_6=$(openssl rand -hex 4)
KEK_2_7=$(openssl rand -hex 4)

# Format KEK in space-separated format (for command line tools)
KEK_2_KEY=$(echo "0x${KEK_2_0} 0x${KEK_2_1} 0x${KEK_2_2} 0x${KEK_2_3} 0x${KEK_2_4} 0x${KEK_2_5} 0x${KEK_2_6} 0x${KEK_2_7}")
echo "${KEK_2_KEY}" > kek.key

# Format KEK in continuous format with 0x prefix (for XML)
KEK_2_KEY_XML="0x${KEK_2_0}${KEK_2_1}${KEK_2_2}${KEK_2_3}${KEK_2_4}${KEK_2_5}${KEK_2_6}${KEK_2_7}"
echo "${KEK_2_KEY_XML}" > kek_xml.key

# Format KEK in continuous format without 0x prefix (for OP-TEE)
KEK_2_KEY_OPTEE="${KEK_2_0}${KEK_2_1}${KEK_2_2}${KEK_2_3}${KEK_2_4}${KEK_2_5}${KEK_2_6}${KEK_2_7}"
echo "${KEK_2_KEY_OPTEE}" > kek_optee.key

# Generate symmetric keys for T234 SoC
openssl rand -rand /dev/urandom -hex 32 > sym_t234.key   # 256-bit primary symmetric key
openssl rand -rand /dev/urandom -hex 16 > sym2_t234.key  # 128-bit secondary symmetric key
openssl rand -rand /dev/urandom -hex 16 > auth_t234.key  # 128-bit authentication key

# Generate UEFI Secure Boot keys
# UEFI Secure Boot uses a chain of trust with multiple key types:
# - PK (Platform Key): The root of trust, owned by platform owner
# - KEK (Key Exchange Key): Used to update the signature database
# - db (Signature Database): Contains keys that are allowed to boot

mkdir uefi_keys
cd uefi_keys
GUID=$(uuidgen)  # Generate a unique GUID for the EFI signature lists

# Generate PK (Platform Key) - RSA Key Pair, Certificate, and EFI Signature List File
# This is the root key for UEFI Secure Boot
openssl req -newkey rsa:2048 -nodes -keyout PK.key  -new -x509 -sha256 -days 3650 -subj "/CN=my Platform Key/" -out PK.crt
cert-to-efi-sig-list -g "${GUID}" PK.crt PK.esl  # Convert certificate to EFI signature list

# Generate KEK (Key Exchange Key) - RSA Key Pair, Certificate, and EFI Signature List File
# This key is used to sign updates to the signature database
openssl req -newkey rsa:2048 -nodes -keyout KEK.key  -new -x509 -sha256 -days 3650 -subj "/CN=my Key Exchange Key/" -out KEK.crt
cert-to-efi-sig-list -g "${GUID}" KEK.crt KEK.esl  # Convert certificate to EFI signature list

# Generate db_1 (Signature Database key 1) - RSA Key Pair, Certificate, and EFI Signature List File
# This key is used to sign bootable UEFI applications and drivers
openssl req -newkey rsa:2048 -nodes -keyout db_1.key  -new -x509 -sha256 -days 3650 -subj "/CN=my Signature Database key/" -out db_1.crt
cert-to-efi-sig-list -g "${GUID}" db_1.crt db_1.esl  # Convert certificate to EFI signature list

# Generate db_2 (Signature Database key 2) - RSA Key Pair, Certificate, and EFI Signature List File
# Additional key for signing bootable UEFI applications and drivers
openssl req -newkey rsa:2048 -nodes -keyout db_2.key  -new -x509 -sha256 -days 3650 -subj "/CN=my another Signature Database key/" -out db_2.crt
cert-to-efi-sig-list -g "${GUID}" db_2.crt db_2.esl  # Convert certificate to EFI signature list

# Create UEFI keys configuration file
# This file defines which keys will be used in the UEFI secure boot process

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
# This contains encrypted keys for secure OS (OP-TEE) operations
mkdir bootloader
python3 $GENEKB  -chip t234 -oem_k1_key kek_optee.key -in_sym_key sym_t234.key \
                 -in_sym_key2 sym2_t234.key -in_auth_key auth_t234.key \
                 -out bootloader/eks_t234.img


# Generate fuse programming XML file
# This file defines the values to be programmed into the device's secure fuses
echo "<genericfuse MagicId=\"0x45535546\" version=\"1.0.0\">" > fuse.xml
echo "  <fuse name=\"PublicKeyHash\" size=\"64\" value=\"${PKCS_KEY_XML_HASH}\"/>" >> fuse.xml  # RSA public key hash
echo "  <fuse name=\"SecureBootKey\" size=\"32\" value=\"${SBK_KEY_XML}\"/>" >> fuse.xml       # Secure Boot Key
echo "  <fuse name=\"OemK1\" size=\"32\" value=\"${KEK_2_KEY_XML}\"/>" >> fuse.xml             # OEM Key (KEK)
echo "  <fuse name=\"BootSecurityInfo\" size=\"4\" value=\"0x209\"/>" >> fuse.xml              # Boot security configuration
echo "  <fuse name=\"SecurityMode\" size=\"4\" value=\"0x1\"/>" >> fuse.xml                    # Security mode (1=secure)
echo "</genericfuse>" >> fuse.xml

