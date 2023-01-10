#  Copyright 2023 Sota Kondo

#  Permission is hereby granted, free of charge, to any person obtaining
#  a copy of this software and associated documentation files (the "Software"),
#  to deal in the Software without restriction, including without limitation
#  the rights to use, copy, modify, merge, publish, distribute, sublicense,
#  and/or sell copies of the Software, and to permit persons to whom the
#  Software is furnished to do so, subject to the following conditions:

#  The above copyright notice and this permission notice shall be included
#  in all copies or substantial portions of the Software.

#  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
#  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
#  OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
#  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
#  DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
#  TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
#  OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.


import numpy as np
import pyshark


class BFFDecoder(object):
    def __init__(self):
        self.nc = None
        self.nr = None
        self.num_subcarrier = None
        self.nbits_phi = None
        self.nbits_psi = None
        self.num_iter = None
        self.num_phi_psi = None
        self.num_phi_psi_list = None

    def _set_bfm_fmt(self, nc, nr, num_subcarrier, nbits_phi, nbits_psi):
        self.nc = nc
        self.nr = nr
        self.num_subcarrier = num_subcarrier
        self.nbits_phi = nbits_phi
        self.nbits_psi = nbits_psi

        self.num_iter = min(self.nc, self.nr - 1)

        self.num_phi_psi = 0
        self.num_phi_psi_list = []
        for i in range(self.num_iter):
            self.num_phi_psi += self.nr - 1 - i
            self.num_phi_psi_list.append(self.nr - 1 - i)
        self.num_phi_psi_list.append(0)

    def _decode_bfm_packet(self, raw_bfm_data_packet):
        ret = []
        bits_vmat_per_subcarrier = self.num_phi_psi * (self.nbits_phi + self.nbits_psi)
        mask_subcarrier = (1 << bits_vmat_per_subcarrier) - 1

        for i in range(self.num_subcarrier):
            shift_subcarrier = (self.num_subcarrier - i - 1) * bits_vmat_per_subcarrier

            sub = (raw_bfm_data_packet >> shift_subcarrier) & mask_subcarrier

            ret.append(self.__decode_bfm_subcarrier(sub))

        return np.array(ret, dtype=np.uint8)

    def __decode_bfm_subcarrier(self, sub):
        mask_phi = (1 << self.nbits_phi) - 1
        mask_psi = (1 << self.nbits_psi) - 1

        ret_phi = []
        ret_psi = []
        ret_phi_and_psi = []

        for j in range(self.num_iter):
            n = self.nr - j - 1
            for k in range(n):
                shift_phi = sum(self.num_phi_psi_list[j:]) * self.nbits_psi
                shift_phi += sum(self.num_phi_psi_list[j + 1 :]) * self.nbits_phi
                shift_phi += (n - 1 - k) * self.nbits_phi
                ret_phi.append((sub >> shift_phi) & mask_phi)
                ret_phi_and_psi.append((sub >> shift_phi) & mask_phi)
            for k in range(n):
                shift_psi = sum(self.num_phi_psi_list[j + 1 :]) * (
                    self.nbits_phi * self.nbits_psi
                )
                shift_psi += (n - 1 - k) * self.nbits_psi
                ret_psi.append((sub >> shift_psi) & mask_psi)
                ret_phi_and_psi.append((sub >> shift_psi) & mask_psi)

        return np.array(ret_phi_and_psi, dtype=np.uint8)

    def _str_to_int_8bit(self, str_8bit):
        ret = int(str_8bit, 16)
        if ret >= 128:
            ret = ret - 256
        return ret

    def _extract_bff_data_ac(self, packet, flag_cbffm):
        nc = packet["wlan.mgt"].wlan_vht_mimo_control_ncindex.hex_value + 1
        nr = packet["wlan.mgt"].wlan_vht_mimo_control_nrindex.hex_value + 1
        streamSNR = [
            self._str_to_int_8bit(snr.raw_value)
            for snr in packet[
                "wlan.mgt"
            ].wlan_vht_compressed_beamforming_report_snr.all_fields
        ]
        codebook_info = packet["wlan.mgt"].wlan_vht_mimo_control_codebookinfo.int_value
        if codebook_info == 0:
            nbits_phi = 4
            nbits_psi = 2
        elif codebook_info == 1:
            nbits_phi = 6
            nbits_psi = 4

        bw = packet["wlan.mgt"].wlan_vht_mimo_control_chanwidth.hex_value
        if bw == 0:
            num_sub = 52
        elif bw == 1:
            num_sub = 108
        else:
            num_sub = 234

        raw_bfm = packet["wlan.mgt"].get("").fields[-1].hex_value

        self._set_bfm_fmt(nc, nr, num_sub, nbits_phi, nbits_psi)
        decoded_bfm = None
        if flag_cbffm is True:
            decoded_bfm = self._decode_bfm_packet(raw_bfm)

        #  Some 11ac beamforming feedback reports do not have mactime.
        if "mactime" not in dir(packet["radiotap"]):
            return None

        return {
            "nr": nr,
            "nc": nc,
            "num_sub": num_sub,
            "streamSNR": 22 + np.array(streamSNR) / 4,
            "CBFFM": decoded_bfm,
            "ta": packet["wlan"].ta.hex_value,
            "ra": packet["wlan"].ra.hex_value,
            "mactime": int(packet["radiotap"].mactime.show),
        }

    def _extract_bff_data_ax(self, packet, flag_cbffm):
        nc = packet["wlan.mgt"].wlan_he_mimo_nc_index.hex_value + 1
        nr = packet["wlan.mgt"].wlan_he_mimo_nr_index.hex_value + 1
        streamSNR = [
            self._str_to_int_8bit(snr.raw_value)
            for snr in packet[
                "wlan.mgt"
            ].wlan_he_mimo_beamforming_report_avgsnr.all_fields
        ]
        codebook_info = packet["wlan.mgt"].wlan_he_mimo_codebook_info.int_value
        if codebook_info == 0:
            nbits_phi = 4
            nbits_psi = 2
        elif codebook_info == 1:
            nbits_phi = 6
            nbits_psi = 4

        bw = packet["wlan.mgt"].wlan_he_mimo_bw.hex_value
        if bw == 0:
            num_sub = 64
        elif bw == 1:
            num_sub = 122
        else:
            num_sub = 250

        raw_bfm = packet["wlan.mgt"].get("").fields[-1].hex_value

        self._set_bfm_fmt(nc, nr, num_sub, nbits_phi, nbits_psi)
        decoded_bfm = None
        if flag_cbffm is True:
            decoded_bfm = self._decode_bfm_packet(raw_bfm)

        return {
            "nr": nr,
            "nc": nc,
            "num_sub": num_sub,
            "streamSNR": 22 + np.array(streamSNR) / 4,
            "CBFFM": decoded_bfm,
            "ta": packet["wlan"].ta.hex_value,
            "ra": packet["wlan"].ra.hex_value,
            "mactime": int(packet["radiotap"].mactime.show),
        }

    def extract_bff_data(self, packet, flag_cbffm=True):
        """
        Extract BFF as iterator
        Parameters
        ----------
        packet : pyshark.packet.packet.Packet
            PCAP file path.
        flag_cbffm : bool
            If false, angle information of beamforming feedback matrices are not extracted.
            Extracting angle information is a heavy process.

        Returns
        ----------
        bff_data : dict
            BFF data in dictionary format.

            keys
            nr : int
                Value of Nr.
            nc : int
                Value of Nc.
            num_sub : int
                Number of the subcarrier.
            streamSNR : numpy.ndarray
                Stream SNR in decibel notation.
            CBFFM : numpy.ndarray
                Angle information of beamforming feedback matrices.
                If "flag_cbffm" is false, this is None.
            ta : str
                Transmitter address
            ra : str
                Receiver address
            mactime : int
                mactime in milliseconds.
        """
        if "wlan.mgt" not in dir(packet) or "wlan_fixed_category_code" not in dir(
            packet["wlan.mgt"]
        ):
            return None

        if packet["wlan.mgt"].wlan_fixed_category_code.hex_value == 21:
            return self._extract_bff_data_ac(packet, flag_cbffm)
        elif packet["wlan.mgt"].wlan_fixed_category_code.hex_value == 30:
            return self._extract_bff_data_ax(packet, flag_cbffm)
        else:
            return None


def iterator_bff(pcap_path, flag_cbffm=True):
    """
    Extract BFF as iterator
    Parameters
    ----------
    pcap_path : str
        PCAP file path.
    flag_cbffm : bool
        If false, angle information of beamforming feedback matrices are not extracted.
        Extracting angle information is a heavy process.

    Yields
    ----------
    bff_data : dict
        BFF data in dictionary format.

        keys
        nr : int
            Value of Nr.
        nc : int
            Value of Nc.
        num_sub : int
            Number of the subcarrier.
        streamSNR : np.ndarray
            Stream SNR in decibel notation.
        CBFFM : np.ndarray
            Angle information of beamforming feedback matrices.
            If "flag_cbffm" is false, this is None.
        ta : str
            Transmitter address
        ra : str
            Receiver address
        mactime : int
            mactime in milliseconds.
    """

    bff_decoder = BFFDecoder()

    cap = pyshark.FileCapture(pcap_path)
    for packet in cap:
        bff_dict = bff_decoder.extract_bff_data(packet, flag_cbffm)
        if bff_dict is not None:
            yield bff_dict
