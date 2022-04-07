# This file is part of Scapy
# Scapy is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# any later version.
#
# Scapy is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Scapy. If not, see <http://www.gnu.org/licenses/>.

#  0                   1                   2                   3
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |  Next Header  |   Hrd Ext Len | R | Crypt Off |S|D|Version|V|1| DW0
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                  Security Params Index (SPI)                  | DW1
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               | DW2
# +                   Initialization Vector (IV)                  +
# |                                                               | DW3
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               | DW4
# +              Virtualization Cookie (VC) [Optional]            +
# |                                                               | DW5
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

# from scapy.contrib.google_p4 import NISP

import json
import enum
import binascii
from scapy.data import IP_PROTOS
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6
from scapy.compat import raw
from scapy.packet import Packet, bind_layers, Raw
from scapy.fields import (
    BitField, BitEnumField,
    XIntField, XLongField,
    ConditionalField
)
from cryptography.hazmat.primitives.ciphers import aead


class NISPError(Exception):
    pass

class NISPKeyLen(enum.IntEnum):
    """
    NISP key length in bytes
    """
    NISPKey128 = 16
    NISPKey256 = 32

class NISPHeaderVersion(enum.IntEnum):
    AES_GCM_128 = 0
    AES_GCM_256 = 1
    AES_GMAC_128 = 2
    AES_GMAC_256 = 3

class NISPCryptOp(enum.IntEnum):
    NISP_ENCRYPT = 0
    NISP_DECRYPT = 1

class NISP(Packet):
    name = 'NISP'

    # UDP destination port
    NISP_DPORT = 1000

    fields_desc = [BitEnumField("next", 4, 8, IP_PROTOS),
                   BitField("ext_len", 0, 8),
                   BitField("r", 0, 2, 16),
                   BitField("crypt_offset", 0, 6, 16),
                   BitField("s", 0, 1, 16),
                   BitField("d", 0, 1, 16),
                   BitField("version", 0, 4, 16),
                   BitField("v", 0, 1, 16),
                   BitField("one", 1, 1, 16),
                   XIntField("spi", 0),
                   XLongField("iv", 0),
                   ConditionalField(XLongField("vc", 0),
                                    lambda pkt: pkt.ext_len >= 1 and
                                                pkt.v == 1)
                   ]

    def mysummary(self):
        return self.sprintf("Google P4 %NISP.next% %NISP.ext_len%")


    def len(self):
        return 8 + self.ext_len

    def post_build(self, p: bytes, pay: bytes) -> bytes:
        return p + pay

bind_layers(UDP, NISP,  dport=NISP.NISP_DPORT)
bind_layers(NISP, IPv6, next=IP_PROTOS.ipv6)
# IPIP protocol naming in /etc/protocols file
# differs between Linux distributions
if hasattr(IP_PROTOS, 'ipencap'):
    bind_layers(NISP, IP,   next=IP_PROTOS.ipencap)
elif hasattr(IP_PROTOS, 'ipv4'):
    bind_layers(NISP, IP,   next=IP_PROTOS.ipv4)

def nisp_crypt(nisp: NISP, key: bytes, crypt_op: NISPCryptOp) -> NISP:
    """Encrypt NISP packet
    :param nisp: nisp header followed by inner packet
    :key encryption key
    :crypto_op encrypt | decrypt
    :return: nisp header followed by payload
    """
    if nisp.iv is None:
        raise NISPError('NISP header error: empty IV ')
    copy = nisp.copy()
    if len(key) == NISPKeyLen.NISPKey128:
        copy.version = NISPHeaderVersion.AES_GCM_128
    elif len(key) == NISPKeyLen.NISPKey256:
        copy.version = NISPHeaderVersion.AES_GCM_256
    else:
        raise NISPError('NISP protocol error: invalid key length:' + str(len(key)))
    blob = raw(copy)
    # NISP.IV offset is 16 bytes
    encrypt_offset = 16 + 4 * nisp.crypt_offset
    nonce = nisp.spi.to_bytes(4, byteorder='big') + \
            nisp.iv.to_bytes(8, byteorder='big')
    aesgcm = aead.AESGCM(key)
    op = aesgcm.encrypt if crypt_op == NISPCryptOp.NISP_ENCRYPT \
         else aesgcm.decrypt
    data = op(nonce, blob[encrypt_offset:], blob[:encrypt_offset])
    return NISP(blob[:encrypt_offset] + data)


def nisp_encap(outer: Ether,
               nisp: NISP, packet: Ether,
               key = None) -> Ether:
    """Add outer NISP tunnel


    :param outer: outer L2 and L3 layers
    :param nisp: NISP header
    :param packet: original packet
    :param key encryption key (optional)
    :return: tunneled NISP packet
    """
    l3 = IP if IP in packet else IPv6
    inner = nisp / packet[l3]
    if not key is None:
        inner = nisp_crypt(inner, key, NISPCryptOp.NISP_ENCRYPT)
    else:
        inner = inner / Raw('\x00' * 16)
    return outer.copy() / UDP(sport=12345)/ inner

def nisp_decap(tunnel: Ether, l2: Ether, key = None) -> Ether:
    """Remove NISP tunnel, add L2 layer
    """
    inner = tunnel[NISP]
    if hasattr(IP_PROTOS, 'ipencap'):
        inner_ip4=IP_PROTOS.ipencap
    elif hasattr(IP_PROTOS, 'ipv4'):
        inner_ip4=IP_PROTOS.ipv4
    if not key is None:
        inner = nisp_crypt(inner, key, NISPCryptOp.NISP_DECRYPT)
    l3 = inner[IP] if inner[NISP].next == inner_ip4 \
        else inner[IPv6]
    return l2.copy() / l3

def nisp_key_import(filename:str) -> 'dict':
    """ Import NISP encryption key
    :param filename: JSON file name
    :return: dictionary
    JSON file format:
    {
        "key": <data>,
        "spi": <data>,
        "size": <data>
    }
    """
    f = open(filename)
    dict = json.load(f)
    dict['key'] = binascii.unhexlify(dict['key'])
    f.close()
    return dict

