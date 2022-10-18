from asyncore import read
import json
from pylibpcap.pcap import rpcap
from pathlib import Path
import yaml
import binascii
import ruamel.yaml.scalarstring

FILENAME = 'trace-27.pcap'

frameNumber = 0
vystup = {"name": "PKS2022/23", "pcap_name": FILENAME, "packets":[], "ipv4_senders":[], "max_send_packets_by":list()}

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
                bin_offset = bin_offset & 0b00011111
                frag_offset = int(str(bin_offset), 10) * 8 + 68
                if (protocol == "TCP" or protocol == "UDP") :
                    src_port = int(hex_packet[frag_offset:frag_offset+4], 16)
                    dst_port = int(hex_packet[frag_offset+4:frag_offset+8], 16)
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


    yaml = ruamel.yaml.YAML()
    yaml.default_flow_style = False
    with open(str(Path(__file__).parent) +'/output.yaml', 'w') as output:
        yaml.dump(vystup, output)

def uloha4() :
    p = input("Zadaj nazov protokolu: ")
    if p in TCP_PORTs.values() : 
        uloha4_tcp()
    elif p == "TFTP" or p == "DHCP" or p == "RIP":
        uloha4_udp()
    elif p == "ICMP":
        uloha4_arp()
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
    print('icmp')  
def uloha4_arp():
    print('arp')  

while(1) :
    i = input("[1] Ulohy 1 2 3\n[2] Uloha 4\n[0] Ukoncit program\n")
    if i == '1':
        ulohy123()
    elif i == '2':
        uloha4()
    elif i == '0':
        break
