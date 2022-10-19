from asyncore import read
import enum
import json
from struct import pack
from sys import flags
from typing_extensions import Self
from urllib.parse import non_hierarchical
from pylibpcap.pcap import rpcap
from pathlib import Path
import yaml
import binascii
import ruamel.yaml.scalarstring

FILENAME = 'trace-27.pcap'

class Packet:
    def __init__(self, frame_number = None, len_frame_pcap = None, len_frame_medium = None, frame_type = None, 
    src_mac = None, dst_mac = None, ether_type = None, sap = None, pid = None, src_ip = None, dst_ip = None, 
    flags_mf = None, frag_offset = None, protocol = None, icmp_type = None, src_port = None, dst_port = None, 
    app_protocol = None, hexa_frame = None, hex_packet = None):
        self.frame_number = frame_number
        self.len_frame_pcap = len_frame_pcap
        self.len_frame_medium = len_frame_medium
        self.frame_type = frame_type
        self.src_mac = src_mac
        self.dst_mac = dst_mac
        self.ether_type = ether_type
        self.sap = sap
        self.pid = pid
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.flags_mf = flags_mf
        self.frag_offset = frag_offset
        self.protocol = protocol
        self.icmp_type = icmp_type
        self.src_port = src_port
        self.dst_port = dst_port
        self.app_protocol = app_protocol
        self.hexa_frame = hexa_frame
        self.hex_packet = hex_packet
    seq = None
    paired = False

packets = []
vystup = {"name": "PKS2022/23", "pcap_name": FILENAME, "packets":[], "ipv4_senders":[], "max_send_packets_by":list(), "communication": list(), "partial_communication": list()}

with open(str(Path(__file__).parent)+'/LSAPs.txt') as f:
    LSAPs_data = f.read()
LSAPs = json.loads(LSAPs_data)

with open(str(Path(__file__).parent)+'/ETHERTYPEs.txt') as f:
    ETHERTYPEs_data = f.read()
ETHERTYPEs = json.loads(ETHERTYPEs_data)

with open(str(Path(__file__).parent)+'/IP_PROTOCOLs.txt') as f:
    IPPROTOCOLs_data = f.read()
IPPROTOCOLs = json.loads(IPPROTOCOLs_data)

with open(str(Path(__file__).parent)+'/TCP_PORTs.txt') as f:
    TCP_PORTs_data = f.read()
TCP_PORTs = json.loads(TCP_PORTs_data)

ip_list = {}

sap = None
ether_type = None
protocol = None
src_port = None
dst_port = None
app_protocol = None

packetList = rpcap(str(Path(__file__).parent)+'/vzorky_pcap_na_analyzu/'+FILENAME)

def ulohy123():
    global packets
    global vystup
    frameNumber = 0
    for packet in packetList:
        packet = packet[2]
        hex_packet = binascii.hexlify(bytes(packet)).decode("utf-8")
        frameNumber += 1
        len_frame_pcap = len(packet)
        if (len_frame_pcap + 4) > 64:
            len_frame_medium = len_frame_pcap + 4
        else :
            len_frame_medium = 64

        sap = None
        ether_type = None
        protocol = None
        src_port = None
        dst_port = None
        app_protocol = None
        flags_mf = None
        src_ip = None
        dst_ip = None
        bin_offset = None
        frag_offset = None
        
        if int((hex_packet[24:28]), 16) > int("5DC", 16):
            frame_type = "ETHERNET II"
            try :
                ether_type = ETHERTYPEs[hex_packet[24:28]]
            except :
                ether_type = "Unknown " + str(hex_packet[24:28])
            if ether_type == "IPv4" :
                try :
                    protocol = IPPROTOCOLs[str(int(hex_packet[46:48], 16))]
                except :
                    protocol = "Unknown " + str(int(hex_packet[46:48], 16))
                    
                src_ip = str(int(hex_packet[52:54],16))+'.'+str(int(hex_packet[54:56],16))+'.'+str(int(hex_packet[56:58],16))+'.'+str(int(hex_packet[58:60],16))
                dst_ip = str(int(hex_packet[60:62],16))+'.'+str(int(hex_packet[62:64],16))+'.'+str(int(hex_packet[64:66],16))+'.'+str(int(hex_packet[66:68],16))

                if src_ip in ip_list :
                    ip_list[src_ip] += 1
                else :
                    ip_list[src_ip] = 1

                bin_offset = int(bin(int(hex_packet[40:44], 16)), 2)
                flags_mf = bool(bin_offset & 0b0010000000000000)
                bin_offset = bin_offset & 0b0001111111111111
                frag_offset = int(str(bin_offset), 10) * 8
                if (protocol == "TCP" or protocol == "UDP") :
                    src_port = int(hex_packet[frag_offset+68:frag_offset+72], 16)
                    dst_port = int(hex_packet[frag_offset+72:frag_offset+76], 16)
                    try :
                        app_protocol = TCP_PORTs[str(min(src_port, dst_port))]
                    except :
                        app_protocol = None

        else :
            if hex_packet[28:32] == "ffff":
                frame_type = "IEEE 802.3 Raw"
            else :
                if hex_packet[28:32] == "aaaa":
                    frame_type = "IEEE 802.3 LLC & SNAP"
                else:
                    frame_type = "IEEE 802.3 LLC"
                    try :
                        sap = LSAPs[hex_packet[32:34]]    
                    except :
                        sap = "Unknown " + str(hex_packet[32:34])

        hexa_frame = ""
        i = 1
        for char in hex_packet:
            if i % 2 == 0:
                if i == 32:
                    hexa_frame += str(char).upper() + "\n"
                    i = 1
                else:
                    hexa_frame += str(char).upper() + " "
                    i += 1        
            else:
                hexa_frame += str(char).upper()
                i += 1
                
        dst_mac = hex_packet[0:12]
        dst_mac = ':'.join(dst_mac[i:i+2].upper() for i in range(0,12,2))    
        src_mac = hex_packet[12:24]
        src_mac = ':'.join(src_mac[i:i+2].upper() for i in range(0,12,2))

        packets.append(Packet(frameNumber, len_frame_pcap, len_frame_medium, frame_type, src_mac, dst_mac, ether_type, 
        sap, None, src_ip, dst_ip, flags_mf, frag_offset, protocol, None, src_port, dst_port, app_protocol, hexa_frame, hex_packet))
        if(src_port) :        
            if (app_protocol) :
                vystup["packets"].append({"frame_number":frameNumber, "len_frame_pcap":len_frame_pcap, "len_frame_medium":len_frame_medium, "frame_type":frame_type, "src_mac":src_mac, "dst_mac":dst_mac, "ether_type":ether_type, "src_ip":src_ip, "dst_ip":dst_ip, "frag_offset":frag_offset, "protocol":protocol, "src_port":src_port, "dst_port":dst_port, "app_protocol":app_protocol, "hexa_frame":ruamel.yaml.scalarstring.LiteralScalarString(hexa_frame)})
            else :
                vystup["packets"].append({"frame_number":frameNumber, "len_frame_pcap":len_frame_pcap, "len_frame_medium":len_frame_medium, "frame_type":frame_type, "src_mac":src_mac, "dst_mac":dst_mac, "ether_type":ether_type, "src_ip":src_ip, "dst_ip":dst_ip, "frag_offset":frag_offset, "protocol":protocol, "src_port":src_port, "dst_port":dst_port, "hexa_frame":ruamel.yaml.scalarstring.LiteralScalarString(hexa_frame)})
        elif (protocol) :
            vystup["packets"].append({"frame_number":frameNumber, "len_frame_pcap":len_frame_pcap, "len_frame_medium":len_frame_medium, "frame_type":frame_type, "src_mac":src_mac, "dst_mac":dst_mac, "ether_type":ether_type, "src_ip":src_ip, "dst_ip":dst_ip, "protocol":protocol, "hexa_frame":ruamel.yaml.scalarstring.LiteralScalarString(hexa_frame)})
        elif (ether_type) :
            vystup["packets"].append({"frame_number":frameNumber, "len_frame_pcap":len_frame_pcap, "len_frame_medium":len_frame_medium, "frame_type":frame_type, "src_mac":src_mac, "dst_mac":dst_mac, "ether_type":ether_type, "hexa_frame":ruamel.yaml.scalarstring.LiteralScalarString(hexa_frame)})
        elif (sap) :
            vystup["packets"].append({"frame_number":frameNumber, "len_frame_pcap":len_frame_pcap, "len_frame_medium":len_frame_medium, "frame_type":frame_type, "src_mac":src_mac, "dst_mac":dst_mac, "sap":sap, "hexa_frame":ruamel.yaml.scalarstring.LiteralScalarString(hexa_frame)})
        else :
            vystup["packets"].append({"frame_number":frameNumber, "len_frame_pcap":len_frame_pcap, "len_frame_medium":len_frame_medium, "frame_type":frame_type, "src_mac":src_mac, "dst_mac":dst_mac, "hexa_frame":ruamel.yaml.scalarstring.LiteralScalarString(hexa_frame)})

    max_sent = max(ip_list.values())
    packet_senders = list()
    for k, v in ip_list.items():
        vystup["ipv4_senders"].append({"node": k, "number_of_sent_packets": v})
        if v == max_sent:
            packet_senders.append(k)
    vystup["max_send_packets_by"] = packet_senders


def uloha4() :
    p = input("Zadaj nazov protokolu: ").upper()
    if p in TCP_PORTs.values() : 
        uloha4_tcp()
    elif p == "TFTP" or p == "DHCP" or p == "RIP":
        uloha4_udp()
    elif p == "ICMP":
        uloha4_icmp()
    elif p == "ARP":
        uloha4_arp()
    else:
        print("Nespravny protokol\n")
        return

def uloha4_tcp():
    print('tcp')   
def uloha4_udp():
    print('udp')  

def uloha4_icmp():
    comms = list()
    global packets
    global vystup
    for p in packets:
        if p.frame_type == "ETHERNET II" and p.ether_type == "IPv4" and p.protocol == "ICMP":
                p.icmp_type = p.hex_packet[p.frag_offset+68:p.frag_offset+70]
                if p.icmp_type == '08' :
                    p.icmp_type = "ECHO REQUEST"
                elif p.icmp_type == '00' :
                    p.icmp_type = "ECHO REPLY"

                if p.frag_offset > 68 :
                    p.seq = p.hex_packet[p.frag_offset+80:p.frag_offset+84]
                comms.append(p)

    n_com = 0
    for i, p in enumerate(comms) :
        if (p.seq) and (not p.paired):
            for j, p2 in enumerate(comms) :
                if(p2.seq) and (p != p2) and (not p2.paired):
                    if p.seq == p2.seq :
                        n_com += 1
                        vystup["communication"].append({"number_comm": n_com, "packets": [
                            {"frame_number":comms[i-1].frame_number, "len_frame_pcap":comms[i-1].len_frame_pcap, "len_frame_medium":comms[i-1].len_frame_medium,
                            "frame_type":comms[i-1].frame_type, "src_mac":comms[i-1].src_mac, "dst_mac":comms[i-1].dst_mac, "ether_type":comms[i-1].ether_type, "src_ip":comms[i-1].src_ip,
                            "dst_ip":comms[i-1].dst_ip, "id":int(comms[i-1].hex_packet[36:40], 16), "flags_mf": comms[i-1].flags_mf, "frag_offset":comms[i-1].frag_offset,
                            "hexa_frame":ruamel.yaml.scalarstring.LiteralScalarString(comms[i-1].hexa_frame)},
                            {"frame_number":p.frame_number, "len_frame_pcap":p.len_frame_pcap, "len_frame_medium":p.len_frame_medium,
                            "frame_type":p.frame_type, "src_mac":p.src_mac, "dst_mac":p.dst_mac, "ether_type":p.ether_type, "src_ip":p.src_ip,
                            "dst_ip":p.dst_ip, "id":int(comms[i-1].hex_packet[36:40], 16), "flags_mf": p.flags_mf, "frag_offset":p.frag_offset, "protocol":p.protocol, "icmp_type":comms[i-1].icmp_type,
                            "hexa_frame":ruamel.yaml.scalarstring.LiteralScalarString(p.hexa_frame)},
                            {"frame_number":comms[j-1].frame_number, "len_frame_pcap":comms[j-1].len_frame_pcap, "len_frame_medium":comms[j-1].len_frame_medium,
                            "frame_type":comms[j-1].frame_type, "src_mac":comms[j-1].src_mac, "dst_mac":comms[j-1].dst_mac, "ether_type":comms[j-1].ether_type, "src_ip":comms[j-1].src_ip,
                            "dst_ip":comms[j-1].dst_ip, "id":int(comms[i-1].hex_packet[36:40], 16), "flags_mf": comms[j-1].flags_mf, "frag_offset":comms[j-1].frag_offset,
                            "hexa_frame":ruamel.yaml.scalarstring.LiteralScalarString(comms[j-1].hexa_frame)},
                            {"frame_number":p2.frame_number, "len_frame_pcap":p2.len_frame_pcap, "len_frame_medium":p2.len_frame_medium,
                            "frame_type":p2.frame_type, "src_mac":p2.src_mac, "dst_mac":p2.dst_mac, "ether_type":p2.ether_type, "src_ip":p2.src_ip,
                            "dst_ip":p2.dst_ip, "id":int(comms[i-1].hex_packet[36:40], 16), "flags_mf": p2.flags_mf, "frag_offset":p2.frag_offset, "protocol":p2.protocol, "icmp_type":comms[j-1].icmp_type,
                            "hexa_frame":ruamel.yaml.scalarstring.LiteralScalarString(p2.hexa_frame)}
                        ]})
                        p.paired = True
                        comms[i-1].paired = True
                        p2.paired = True
                        comms[j-1].paired = True

    n_com = 0
    for p in comms :
        if (not p.paired):
            n_com += 1
            vystup["partial_communication"].append({"number_comm": n_com, "packets":
                {"frame_number":p.frame_number, "len_frame_pcap":p.len_frame_pcap, "len_frame_medium":p.len_frame_medium,
                "frame_type":p.frame_type, "src_mac":p.src_mac, "dst_mac":p.dst_mac, "ether_type":p.ether_type, "src_ip":p.src_ip,
                "dst_ip":p.dst_ip, "id":int(p.hex_packet[36:40], 16), "flags_mf": p.flags_mf, "frag_offset":p.frag_offset,
                "hexa_frame":ruamel.yaml.scalarstring.LiteralScalarString(p.hexa_frame)}})
                        
        
def uloha4_arp():
    print('arp')  

while(1) :
    i = input("[1] Ulohy 1 2 3\n[2] Uloha 4\n[0] Ukoncit program\n")
    if i == '1':
        ulohy123()
        yaml = ruamel.yaml.YAML()
        yaml.default_flow_style = False
        with open(str(Path(__file__).parent) +'/output.yaml', 'w') as output:
            yaml.dump(vystup, output)
    elif i == '2':
        ulohy123()
        uloha4()
        yaml = ruamel.yaml.YAML()
        yaml.default_flow_style = False
        with open(str(Path(__file__).parent) +'/output.yaml', 'w') as output:
            yaml.dump(vystup, output)
    elif i == '0':
        break
    
