# Beamforming Feedback (BFF) decoder

BFF is the radio frequency information in IEEE 802.11ac standard or later standards. Since the BFF is recorded unencrypted in the frame, the BFF can be obtained by collecting the frame. This program extracts the BFF from the frame capture output data, which is obtained as a PCAP file. This program supports the BFF of the IEEE 802.11ac/ax standard.

If you would like more information about BFF, we suggest you visit the following sites.
- [O'Reilly](https://www.oreilly.com/library/view/80211ac-a-survival/9781449357702/ch04.html)
- [MathWorks](https://jp.mathworks.com/help/wlan/ug/802-11ac-transmit-beamforming.html)
- [youtube](https://www.youtube.com/watch?v=iy3AyfXRMzw)

## Requirement

- numpy
- pyshark
- [tshark](https://github.com/wireshark/wireshark)


## Usage

sample.py is an example of usage.

```python
import bffdecoder

pcap_path = "./data/sample_ac.pcap"
for bff_dict in bff_decoder.iterator_bff(pcap_path, True):
    print(bff_dict)
```

```python
import bffdecoder

pcap_path = "./data/sample_ax.pcap"
cap = pyshark.FileCapture(pcap_path)
packet = cap[120]

decoder = bffdecoder.BFFDecoder()

bff_dict = decoder.extract_bff_data(packet)
print(bff_dict["CBFFM"]) # angle information of BFF matrices
```


## Publications

- [Bi-Directional Beamforming Feedback-Based Firmware-Agnostic WiFi Sensing: An Empirical Study](https://ieeexplore.ieee.org/abstract/document/9749267) IEEE Access 2022.
- [Respiratory Rate Estimation Based on WiFi Frame Capture](https://ieeexplore.ieee.org/abstract/document/9700721) IEE CCNC 2022.
