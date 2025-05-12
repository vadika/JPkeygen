#!/bin/bash
#

set -e

TEGRASIGN="../JP/Linux_for_Tegra/bootloader/tegrasign_v3.py"
UEFIDTSGEN="../JP/Linux_for_Tegra/tools/gen_uefi_keys_dts.sh"
GENEKB="../JP/Linux_for_Tegra/source/optee/samples/hwkey-agent/host/tool/gen_ekb/gen_ekb.py"

openssl genrsa -out rsa.pem 3072
PKCS_KEY_XML_HASH=$($TEGRASIGN --pubkeyhash rsa.pubkey rsa.hash --key rsa.pem | grep "tegra-fuse format" | awk '{print $NF}')
SBK_0=$(openssl rand -hex 4)
SBK_1=$(openssl rand -hex 4)
SBK_2=$(openssl rand -hex 4)
SBK_3=$(openssl rand -hex 4)
SBK_4=$(openssl rand -hex 4)
SBK_5=$(openssl rand -hex 4)
SBK_6=$(openssl rand -hex 4)
SBK_7=$(openssl rand -hex 4)
SBK_KEY=$(echo "0x${SBK_0} 0x${SBK_1} 0x${SBK_2} 0x${SBK_3} 0x${SBK_4} 0x${SBK_5} 0x${SBK_6} 0x${SBK_7}")
echo "${SBK_KEY}" > sbk.key
SBK_KEY_XML="0x${SBK_0}${SBK_1}${SBK_2}${SBK_3}${SBK_4}${SBK_5}${SBK_6}${SBK_7}"
echo "${SBK_KEY_XML}" > sbk_xml.key
KEK_2_0=$(openssl rand -hex 4)
KEK_2_1=$(openssl rand -hex 4)
KEK_2_2=$(openssl rand -hex 4)
KEK_2_3=$(openssl rand -hex 4)
KEK_2_4=$(openssl rand -hex 4)
KEK_2_5=$(openssl rand -hex 4)
KEK_2_6=$(openssl rand -hex 4)
KEK_2_7=$(openssl rand -hex 4)
KEK_2_KEY=$(echo "0x${KEK_2_0} 0x${KEK_2_1} 0x${KEK_2_2} 0x${KEK_2_3} 0x${KEK_2_4} 0x${KEK_2_5} 0x${KEK_2_6} 0x${KEK_2_7}")
echo "${KEK_2_KEY}" > kek.key
KEK_2_KEY_XML="0x${KEK_2_0}${KEK_2_1}${KEK_2_2}${KEK_2_3}${KEK_2_4}${KEK_2_5}${KEK_2_6}${KEK_2_7}"
echo "${KEK_2_KEY_XML}" > kek_xml.key
KEK_2_KEY_OPTEE="${KEK_2_0}${KEK_2_1}${KEK_2_2}${KEK_2_3}${KEK_2_4}${KEK_2_5}${KEK_2_6}${KEK_2_7}"
echo "${KEK_2_KEY_OPTEE}" > kek_optee.key

openssl rand -rand /dev/urandom -hex 32 > sym_t234.key
openssl rand -rand /dev/urandom -hex 16 > sym2_t234.key
openssl rand -rand /dev/urandom -hex 16 > auth_t234.key

# Generate UEFI keys
#

mkdir uefi_keys
cd uefi_keys
GUID=$(uuidgen)
# Generate PK RSA Key Pair, Certificate, and EFI Signature List File

openssl req -newkey rsa:2048 -nodes -keyout PK.key  -new -x509 -sha256 -days 3650 -subj "/CN=my Platform Key/" -out PK.crt
cert-to-efi-sig-list -g "${GUID}" PK.crt PK.esl

# Generate KEK RSA Key Pair, Certificate, and EFI Signature List File
openssl req -newkey rsa:2048 -nodes -keyout KEK.key  -new -x509 -sha256 -days 3650 -subj "/CN=my Key Exchange Key/" -out KEK.crt
cert-to-efi-sig-list -g "${GUID}" KEK.crt KEK.esl

# Generate db_1 RSA Key Pair, Certificate, and EFI Signature List File

openssl req -newkey rsa:2048 -nodes -keyout db_1.key  -new -x509 -sha256 -days 3650 -subj "/CN=my Signature Database key/" -out db_1.crt
cert-to-efi-sig-list -g "${GUID}" db_1.crt db_1.esl

# Generate db_2 RSA Key Pair, Certificate, and EFI Signature List File

openssl req -newkey rsa:2048 -nodes -keyout db_2.key  -new -x509 -sha256 -days 3650 -subj "/CN=my another Signature Database key/" -out db_2.crt
cert-to-efi-sig-list -g "${GUID}" db_2.crt db_2.esl

# Create uefi_keys.conf file
#

cat > "uefi_keys.conf" << EOF
UEFI_DB_1_KEY_FILE="db_1.key";  # UEFI payload signing key
UEFI_DB_1_CERT_FILE="db_1.crt"; # UEFI payload signing key certificate

UEFI_DEFAULT_PK_ESL="PK.esl"
UEFI_DEFAULT_KEK_ESL_0="KEK.esl"

UEFI_DEFAULT_DB_ESL_0="db_1.esl"
UEFI_DEFAULT_DB_ESL_1="db_2.esl"
EOF

cd ..
sudo $UEFIDTSGEN uefi_keys/uefi_keys.conf


# Generating the OP-TEE image
#
mkdir bootloader
python3 $GENEKB  -chip t234 -oem_k1_key kek_optee.key -in_sym_key sym_t234.key -in_sym_key2 sym2_t234.key -in_auth_key auth_t234.key -out bootloader/eks_t234.img


# FUSE file generation
#
echo "<genericfuse MagicId=\"0x45535546\" version=\"1.0.0\">" > fuse.xml
echo "  <fuse name=\"PublicKeyHash\" size=\"64\" value=\"${PKCS_KEY_XML_HASH}\"/>" >> fuse.xml
echo "  <fuse name=\"SecureBootKey\" size=\"32\" value=\"${SBK_KEY_XML}\"/>" >> fuse.xml
echo "  <fuse name=\"OemK1\" size=\"32\" value=\"${KEK_2_KEY_XML}\"/>" >> fuse.xml
echo "  <fuse name=\"BootSecurityInfo\" size=\"4\" value=\"0x209\"/>" >> fuse.xml
echo "  <fuse name=\"SecurityMode\" size=\"4\" value=\"0x1\"/>" >> fuse.xml
echo "</genericfuse>" >> fuse.xml

