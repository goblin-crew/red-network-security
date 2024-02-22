#!/bin/bash
ACTION="${1}"
IFACE="${2}"

if [ "$ACTION" = "on" ]; then
    echo "enabling monitoring mode on wifi-interface [${IFACE}]"
    ifconfig $IFACE down
    iwconfig $IFACE mode monitor
    ifconfig $IFACE up

elif [ "$ACTION" = "off" ]; then
    echo "disabling monitoring mode on wifi-interface [${IFACE}]"

    sudo ifconfig $IFACE down
    sudo iwconfig $IFACE mode managed
    sudo ifconfig $IFACE up
fi

iwconfig