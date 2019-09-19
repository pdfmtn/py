# import os
# import scapy
# import pcapng
# from scapy.utils import rdpcap
#
# capture = "capture.pcapng"
# a = rdpcap(capture)
# #os.system("tshark  -T text -e _ws.col.Info -e png -e frame.time -e data.data -w capturetshark.pcap > Eavesdrop_Data.txt -c 1000")
# os.system("tshark -r capture.pcapng -Y 'udp port 22222' -w capture_udp.pcap")
# sessions = a.sessions()
# for session in sessions:
#     udp_payload = ""
#     for packet in sessions[session]:
#         print packet

import pyshark

udp_payload=[]
capture = pyshark.FileCapture('capture.log',display_filter='udp port 22222')
udp_payload.append(bytearray.fromhex(capture.data.data).decode())

