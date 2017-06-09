#!/bin/sh

set -e

VNME="honssh-venv"
VENV="$(dirname $0)/${VNME}"


if [ ! -x ${VNME} ]; then
	virtualenv -p python2.7 "${VENV}"
fi
. ${VENV}/bin/activate
export PYTHONPATH=":${VENV}"

pip install --upgrade twisted geoip watchdog cryptography pyasn1 paramiko
twistd -y honssh.tac -p honssh.pid -n
