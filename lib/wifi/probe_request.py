from dataclasses import dataclass
from typing import Any, Self

import scapy as sc
from scapy import all as sca
from scapy import sendrecv as scsr
from scapy.layers import dot11 as d11
from scapy.packet import Packet
from scapy.plist import PacketList

import datetime
from datetime import datetime as dt

import json

from collections import UserList
from enum import Enum

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
        return json.dumps({"timestamp": this.timestamp.strftime("%d/%m/%Y | %H:%M:%S"), "mac": this.mac, "ssid": this.ssid})
    
        
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

# << [DATASTRUCTURES]

# [WORKERS] >>
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# internal classes:
    
class StateJumpingException(Exception):
    def __init__(this, msg: str) -> None:
        super().__init__(msg)

class ScanSessionState(Enum):
    unknown = 0
    initialized = 1
    started = 2
    ready = 3
    running = 4
    finished = 5
    joined = 6
    processed = 7
    failed = 8


class Scanner:
    def __init__(this, iface: str, count: int = 0, timeout = None):
        this.__state__: ScanSessionState = ScanSessionState.unknown
        this.__data__: ProbeRequestList | None = None
        this.__sniffer_thread__: scsr.AsyncSniffer | None = None

        this.state = ScanSessionState.initialized

        this.config: dict = {
            'iface': iface,
            'count': count,
            'timeout': timeout,
            'monitor_mode': True
        }

    @property
    def data(this) -> ProbeRequestList | None:
        '''
        Read-Only interface for session-data
        '''

        return this.__data__
    
    @property
    def state(this) -> ScanSessionState:
        '''
        interface for getting Session-State
        '''

        return this.__state__
    
    @property.setter
    def state(this, value: ScanSessionState = ScanSessionState.unknown) -> None:
        '''
        interface for setting state with validation

        (?) some states can only be set after a particular other
        '''

        required_prev_state: list[bool] = []
        always_valid_prev_state: list[bool] = [this.__state_unknown__, this.__state_failed__]

        if isinstance(value, ScanSessionState):
            if value == ScanSessionState.unknown:
                required_prev_state = [True]

            elif value == ScanSessionState.initialized:
                required_prev_state = [this.__state_finished__]

            elif value == ScanSessionState.started:
                required_prev_state = [this.__state_ready__]

            elif value == ScanSessionState.ready:
                required_prev_state = [this.__state_initialized__]

            elif value == ScanSessionState.running:
                required_prev_state = [this.__state_started__]

            elif value == ScanSessionState.finished:
                required_prev_state = [this.__state_joined__, this.__state_processed__]

            elif value == ScanSessionState.joined:
                required_prev_state = [this.__state_running__]

            elif value == ScanSessionState.processed:
                required_prev_state = [this.__state_joined__]

            elif value == ScanSessionState.failed:
                required_prev_state = [True]

            else:
                raise ValueError("submitted state is not registered")
            
            if not True in required_prev_state and not True in always_valid_prev_state:
                raise StateJumpingException(f"Cannot set state [{ScanSessionState(value).name}] after current state [{ScanSessionState(this.state).name}]")
        else:
            raise TypeError(f"cannot set state of type ({type(value).__name__}) --> type must be (ScanSessionState)")

        this.__state__ = value

    @property
    def __state_unknown__(this) -> bool:
        '''
        Read-Only boolean property that indicates if the Session-State is 'unknown'
        '''

        return bool(this.state == ScanSessionState.unknown)

    @property
    def __state_initialized__(this) -> bool:
        '''
        Read-Only boolean property that indicates if the Session-State is 'initialized'
        '''

        return bool(this.state == ScanSessionState.initialized)

    @property
    def __state_started__(this) -> bool:
        '''
        Read-Only boolean property that indicates if the Session-State is 'started'
        '''

        return bool(this.state == ScanSessionState.started)
    
    @property
    def __state_ready__(this) -> bool:
        '''
        Read-Only boolean property that indicates if the Session-State is 'ready'
        '''

        return bool(this.state == ScanSessionState.ready)

    @property
    def __state_running__(this) -> bool:
        '''
        Read-Only boolean property that indicates if the Session-State is 'running'
        '''

        return bool(this.state == ScanSessionState.running)
    
    @property
    def __state_finished__(this) -> bool:
        '''
        Read-Only boolean property that indicates if the Session-State is 'finished'
        '''

        return bool(this.state == ScanSessionState.finished)
    
    @property
    def __state_joined__(this) -> bool:
        '''
        Read-Only boolean property that indicates if the Session-State is 'joined'
        '''

        return bool(this.state == ScanSessionState.joined)
    
    @property
    def __state_processed__(this) -> bool:
        '''
        Read-Only boolean property that indicates if the Session-State is 'processed'
        '''

        return bool(this.state == ScanSessionState.processed)
    
    @property
    def __state_failed__(this) -> bool:
        '''
        Read-Only boolean property that indicates if the Session-State is 'failed'
        '''

        return bool(this.state == ScanSessionState.failed)
    

    def __pre__(this) -> Self:
        '''
        Tasks to Run before Scan (Preparation phase)
        '''
        
        this.__reset__() # ensure no previous data, values etc. are present and the values are as if they where untouched

        # ...

        if this.__sniffer_thread__ == None:
            def handle_packet(pkt):
                if pkt.haslayer(d11.Dot11ProbeReq):
                    prq = ProbeRequest(packet=pkt, timestamp=dt.now())

                    print(f"{prq.timestamp.strftime("%d/%m/%Y | %H:%M:%S")}\t\t[{prq.mac}]\t\t{prq.ssid}")


            this.__sniffer_thread__ = scsr.AsyncSniffer(
                iface=this.config['iface'], 
                count=this.config['count'], 
                monitor=this.config['monitor'], 
                timeout=this.config['timeout'],
                lfilter = lambda pkt: pkt.haslayer(d11.Dot11ProbeReq),
                prn=handle_packet
            )

            this.state = ScanSessionState.ready
        else:
            raise RuntimeError("A Sniffer-Thread is already present, for safety reasons cannot redefine property")

        return this
    
    def __start__(this) -> Self:
        '''
        Starts the Sniffer
        '''

        if this.__sniffer_thread__ != None:
            this.__sniffer_thread__.start()
            this.state = ScanSessionState.started
        else:
            return ValueError("Cannot start Sniffer thread --> sniffer is None")

        
        return this

    def __await_join__(this) -> Self:
        '''
        Joins the Sniffer Thread with main
        (?) waits until Sniffer-Thread has finished, then returns
        '''

        if this.__sniffer_thread__ != None and this.__sniffer_thread__.running:
            this.__sniffer_thread__.join()
            this.state = ScanSessionState.joined
        else:
            return ValueError("Cannot join Sniffer thread --> sniffer is None")

        return this

    def __process_data__(this, data: PacketList) -> Self:
        '''
        Processes the captured data to a [ProbeRequestList]
        ans set the internal '__data__' property to this value
        '''

        this.__data__: ProbeRequestList = ProbeRequestList([])

        for pkt in data:
            if pkt.haslayer(d11.Dot11ProbeReq):
                prq = ProbeRequest(packet=pkt, timestamp=pkt.sent_time)
                this.__data__.append(prq)

        this.state = ScanSessionState.processed
        
        return this

    def __post__(this) -> Self:
        '''
        Tasks after scan was successfully runned and joined
        (!) the post-data processing happens here, but is defined in another method
        '''

        rslt = this.__sniffer_thread__.results
        this.__process_data__(rslt)
        this.state = ScanSessionState.finished

        return this

    def __on_failed_cleanup__(this) -> Self:
        '''
        Cleanup Tasks when Scan(-session) has failed
        '''

        #! TODO

        return this

    def __on_failed__(this) -> None:
        '''
        Handles Scan(-session) failure
        '''

        #! TODO ...
        this.state = ScanSessionState.failed
        
        #! TODO cleanup tasks

        #! TODO Raise Error

    def __stop__(this) -> Self:
        if this.__sniffer_thread__.running:
            this.__sniffer_thread__.stop()

        this.state = ScanSessionState.joined

        return this

    def __reset__(this) -> Self:
        '''
        Resets Session and its Properties to initialized State

        (?) usefull if the Session should be reused or reruned
            or to ensure no previous Data is present

            --> keeps config
        '''

        if this.__sniffer_thread__.running:
            this.__sniffer_thread__.stop()

        this.__state__: ScanSessionState = ScanSessionState.unknown
        this.__data__: ProbeRequestList | None = None
        this.__sniffer_thread__: scsr.AsyncSniffer | None = None

        this.state = ScanSessionState.initialized

        return this
    
    def start(this) -> Self:
        this.__pre__().__start__()

        return this
    
    def stop(this) -> Self:
        this.__stop__().__post__()
    
        return this
    
    def await_result(this) -> Self:
        this.__await_join__().__post__()
        
        return this
    
    def reset(this) -> Self:
        this.__reset__()
        return this
    

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


