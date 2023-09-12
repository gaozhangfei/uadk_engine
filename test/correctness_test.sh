#!/bin/bash
set -x

# Pre-requirement:
#  This test script is based on OpenSSL's unit test utilities.
#  Please make sure, in a openssl git repository, `make` has
#  been run with success.
OPENSSL_GIT_ROOTDIR=/home/guodong/openssl.git
if [ ! -f "$OPENSSL_GIT_ROOTDIR/test/evp_test" ]; then
    echo "openssl ./test/evp_test doesn't exist."
    echo "please run 'make' in OpenSSL."
    exit 1
fi

# settings of uadk_provider paths
TEST_SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
UADK_PROVIDER_FULLPATH="$TEST_SCRIPT_DIR/../src/.libs/uadk_provider.so"

# Determine the test data file
#  If not specified, use 'test/evpciph_sm4.txt'
if [ -z "$1" ]; then
    TEST_DATA_FILE=$TEST_SCRIPT_DIR/evpciph_sm4.txt
else
    # Check if the file path is already absolute
    if [[ "$1" = /*  ]]; then
        TEST_DATA_FILE="$1"
    else
        # Get the current working directory and append the file path
        TEST_DATA_FILE="$(pwd)/$1"
    fi
fi

# create a uadk_provider config file
UADK_PROVIDER_CONF=uadk_provider.conf
cat <<EOF > $UADK_PROVIDER_CONF
# Configuration OpenSSL for uadk_provider
#
# Format of this file please refer to:
#     https://www.openssl.org/docs/man3.0/man5/config.html
#

# These must be in the default section
config_diagnostics = 1
openssl_conf = openssl_init

[openssl_init]
providers = providers

[providers]
uadk_provider = uadk_provider_conf
# default = default_conf

[default_conf]
activate = yes

[uadk_provider_conf]
module = $UADK_PROVIDER_FULLPATH
activate = yes
UADK_CMD_ENABLE_RSA_ENV = 1
UADK_CMD_ENABLE_DH_ENV = 1
UADK_CMD_ENABLE_CIPHER_ENV = 1
UADK_CMD_ENABLE_DIGEST_ENV = 1
UADK_CMD_ENABLE_ECC_ENV = 1
EOF

cp $UADK_PROVIDER_CONF $OPENSSL_GIT_ROOTDIR/test

cd $OPENSSL_GIT_ROOTDIR/test

# list of supported cipher-algorithms
# LD_LIBRARY_PATH=.. \
#   ../apps/openssl list -provider $UADK_PROVIDER_FULLPATH -cipher-algorithms \
#   | grep uadk_provider

LD_LIBRARY_PATH=.. \
  ./evp_test -config $UADK_PROVIDER_CONF \
  $TEST_DATA_FILE

  # $TEST_SCRIPT_DIR/evpciph_sm4.txt
  # ./recipes/30-test_evp_data/evpciph_sm4.txt
  # ./recipes/30-test_evp_data/evpmd_sm3.txt
