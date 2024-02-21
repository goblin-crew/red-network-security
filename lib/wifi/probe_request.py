from dataclasses import dataclass
from typing import Any, Self

import scapy as sc
from scapy import all as sca
from scapy import sendrecv as scsr
from scapy.layers import dot11 as d11
from scapy.packet import Packet

import datetime
from datetime import datetime as dt

import json

from collections import UserList

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# utility-Functions
# =====================

# Exception Types:
class ParamValidationException(Exception):
    def __init__(this, validator_func: function, msg: str = "An Error occured during Parameter-Validation"):
        this.validator_name = validator_func.__name__
        this.msg = f"[{this.validator_name}][ERROR] {msg}"
        super().__init__(this.msg)


# validation-Decorators:
        
def validate_args(validate_func: function, *params, **kwparams):
    def decorator(func: function):
        def wrapper(*args, **kwargs):
            validate_func(wrapper_args=args, wrapper_kwargs=kwargs, *params, **kwparams)
            return func(*args, **kwargs)
        return wrapper
    return decorator

def validate_packet_layer(layer, arg_index: int | None = None):
    def decorator(func: function):
        def wrapper(*args, **kwargs):
            def is_valid_packet(arg_i: int, s: bool = False) -> None:
                if (len(args) - 1) < arg_i: 
                    raise ParamValidationException(validate_packet_layer, f"Parameter-Index {arg_i} out of bound --> args-count: {len(args)}")
                else:
                    if isinstance(args[arg_i], Packet):
                        if not args[arg_i].haslayer(layer): 
                            raise ParamValidationException(validate_packet_layer, f"Value of Packet-Parameter with index: {arg_i} does not have layer: {type(layer).__name__}!!")

                    elif s: raise ParamValidationException(validate_packet_layer, f"Value of Packet-Parameter with index: {arg_i} is not of type: <scapy.packet.Packet> --> instead is: {type(args[arg_i]).__name__}!!")

            if arg_index == None:
                for i in len(args):
                    is_valid_packet(i)
                
            else:
                is_valid_packet(arg_index, True)
                    
            return func(*args, **kwargs)
        return wrapper
    return decorator


# Formating / Parsing / Conversion Decorators


# Other:

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


# The Probe-Request Type
class ProbeRequest:
    @validate_packet_layer(layer=d11.Dot11ProbeReq)
    def __init__(this, packet: Packet, timestamp: datetime.datetime = dt.now(), capture_location=False):
        this.packet: Packet = packet
        this.timestamp: datetime.datetime = timestamp
        this.mac: str = f"{this.packet.addr2}"
        this.bssid: str = this.mac
        this.ssid: str = f"{this.packet.info}"

    def __str__(this) -> str:
        return json.dumps({"timestamp": this.timestamp, "mac": this.mac, "ssid": this.ssid})
    
        
        # [COORDINATES WHERE THE PACKET WAS CAPTURED -- MAY BE IMPLEMENTED LATER]
        # 
        #this.location: geopy.Point | None = None
        #
        #if capture_location:
        #    this.location = geopy.get_current_location()


#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


# Object Class to summarize and manage Probe Request Scan-Results
class ProbeRequestList(UserList):
    def __init__(this, requests: list[ProbeRequest] = []):
        # Only Stores items of type 'ProbeRequest' other are ignored
        super().__init__(item for item in requests if type(item) is ProbeRequest)
    
    # get list item from index --> bsp. abc = pr_lst[10]
    def __getitem__(this, item_index: int) -> ProbeRequest:
        if item_index < len(this.data):
            return this.data[item_index]
        else:
            raise IndexError(f"Index {item_index} out of range ({len(this.data)})")

    # set list item at index --> bsp. pr_lst[3] = abc 
    def __setitem__(this, item_index: int, val: ProbeRequest) -> None:
        if type(val) is ProbeRequest:
            if item_index < len(this.data):
                this.data[item_index] = val
            else:
                raise IndexError(f"Index {item_index} out of range ({len(this.data)})")
        else:
            raise TypeError('Item must be of type (ProbeRequest)')

    def append(this, item: ProbeRequest) -> Self:
        this.data.append(item)
        return this
    
    def remove(this, val: ProbeRequest) -> Self:
        this.data.remove(val)
        return this

    def clear(this) -> Self:
        this.data.clear()
        return this

    def count(this) -> int:
        return this.count()

    def extend(this, other_list: "ProbeRequestList") -> Self:
        if type(other_list) is ProbeRequestList:
            this.data.extend(other_list)
            return this
        else:
            raise TypeError('Item must be of type (ProbeRequestList)')
        
    def pop(this, item_index: int = -1) -> ProbeRequest:
        if item_index >= 0 and item_index < len(this.data) or item_index < 0:
            return this.data.pop(item_index)
        else:
            raise IndexError(f"Index {item_index} out of range ({len(this.data)})")
        
    
    def pop_front(this) -> ProbeRequest | None:
        popped_value: ProbeRequest | None = None

        try: popped_value = this.data.pop(0)
        except IndexError: popped_value = None
        finally: return popped_value

    def sort(this, key: None | Any = None, rev: bool = False) -> Self:
        this.data.sort(key=key, reverse=rev)
        return this

    def sort(this, func: Any) -> Self:
        this.data = func(this.data)
        return this
    
    def reverse(this) -> Self:
        this.data.reverse()
        return this
            
    def filter(this, func: Any) -> 'ProbeRequestList':
        return func(this.data)


#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


# Static Class to scan for Wifi-Client Probe Requests
class Scanner:
    def __init__(this, wifi_iface: str):
        this.iface: str = wifi_iface
        this.sniffer: scsr.AsyncSniffer | None = None

    def scan(this, count: int = 0) -> ProbeRequestList:
        if this.sniffer == None:
            this.__prb_req_list = ProbeRequestList()
            this.sniffer = scsr.AsyncSniffer(iface=this.iface, count=count, prn=this.__handle_packet)

    def __handle_packet(this, packet) -> None:
        if isinstance(packet, Packet):
            if packet.haslayer(d11.Dot11ProbeReq):
                prb_req: ProbeRequest = ProbeRequest(packet=packet, timestamp=dt.now())
                this.__prb_req_list.append(prb_req)
