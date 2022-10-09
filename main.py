from scapy.all import rdpcap
from pathlib import Path
import yaml
import binascii
import ruamel.yaml.scalarstring

FILENAME = 'trace-25.pcap'

frameNumber = 0
vystup = {"pcap_name": FILENAME, "packets":[]}

packetList = rdpcap(str(Path(__file__).parent)+'\\vzorky_pcap_na_analyzu\\'+FILENAME)

for packet in packetList:
    hex_packet = binascii.hexlify(bytes(packet)).decode("utf-8")
    frameNumber += 1
    len_frame_pcap = len(packet)
    if (len_frame_pcap + 4) > 64:
        len_frame_medium = len_frame_pcap + 4
    else :
        len_frame_medium = 64

    if int((hex_packet[24:28]), 16) > int("5DC", 16):
        frame_type = "ETHERNET II"
    elif hex_packet[28:32] == "aaaa":
        frame_type = "IEEE 802.3 - LLC a SNAP"
    elif hex_packet[28:32] == "ffff":
        frame_type = "IEEE 802.3 - Raw"
    else:
        frame_type = "IEEE 802.3 - LLC"

    hexa_frame = ""
    i = 1
    for char in hex_packet:
        if i % 2 == 0:
            if i == 32:   #každých 32 znakov ukončí riadok
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

    vystup["packets"].append({"frame_number":frameNumber, "len_frame_pcap":len_frame_pcap, "len_frame_medium":len_frame_medium, "frame_type":frame_type, "src_mac":src_mac, "dst_mac":dst_mac, "hexa_frame":ruamel.yaml.scalarstring.LiteralScalarString(hexa_frame)})

yaml = ruamel.yaml.YAML()
yaml.default_flow_style = False
with open(str(Path(__file__).parent) +'\\output.yaml', 'w') as output:
    yaml.dump(vystup, output)