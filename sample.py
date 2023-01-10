import pyshark

import bffdecoder

pcap_path = "./data/sample_ac.pcap"
for bff_dict in bffdecoder.iterator_bff(pcap_path, True):
    print(bff_dict)

pcap_path = "./data/sample_ax.pcap"
for bff_dict in bffdecoder.iterator_bff(pcap_path, True):
    print(bff_dict)


pcap_path = "./data/sample_ax.pcap"
cap = pyshark.FileCapture(pcap_path)

packet = cap[120]

decoder = bffdecoder.BFFDecoder()
bff_dict = decoder.extract_bff_data(packet)
print(bff_dict["CBFFM"].shape)
