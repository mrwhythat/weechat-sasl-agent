#! /usr/bin/env python

#
# WeeChat SASL agent for DELEGATED SASL mechanism based on Ledger Nano S
# hardware cryptocurrency wallet
#

import sys
import base64
import struct

from libagent.device.interface import Identity
from ledgerblue.comm import getDongle


class LedgerInterface:
    def __init__(self):
        self.conn = None

    def __enter__(self):
        self.conn = getDongle()
        return self

    def __exit__(self, *args):
        self.conn.close()

    def __identity(self, username, keyid):
        """Expand username and keyid into SLIP-0013/0017 identity object."""
        idn = Identity('irc://{}@{}'.format(username, keyid), '')
        return b''.join(struct.pack('>I', e) for e in idn.get_bip32_address())

    def pubkey(self, username, keyid):
        """
        Extract public key for given username/keyid.

        Extraction is done by sending APDU request:
            INS = 0x02 - return public key;
            P1  = 0x00 - mark APDU as first frame;
            P2  = 0x01 - select NIST256P curve.
        """
        path = self.__identity(username, keyid)
        datalen = bytes([len(path) + 1, len(path) // 4])
        hdr, ins, p1, p2 = b'\x80', b'\x02', b'\x00', b'\x01'
        apdu = hdr + ins + p1 + p2 + datalen + path
        response = self.conn.exchange(apdu)[1:]
        pref = b'\x03' if (response[64] & 1) != 0 else b'\x02'
        return pref + response[1:33]

    def sign(self, username, keyid, challenge):
        """
        Sign challenge data with key, selected by expanding username/keyid.

        Signing is done be sending APDU request:
            INS = 0x06 - sign generic hash;
            P1  = 0x80 - mark APDU as last frame;
            P2  = 0x01 - select NIST256P curve.
        """
        path = self.__identity(username, keyid)
        datalen = bytes([len(path) + len(challenge) + 1, len(path) // 4])
        hdr, ins, p1, p2 = b'\x80', b'\x06', b'\x80', b'\x01'
        apdu = hdr + ins + p1 + p2 + datalen + path + challenge
        response = self.conn.exchange(apdu)
        # decode (R, S) values for resulting signature (from trezor-agent)
        offset = 3
        length = response[offset]
        r = response[offset + 1:offset + 1 + length]
        if r[0] == 0:
            r = r[1:]
        offset = offset + 1 + length + 1
        length = response[offset]
        s = response[offset + 1:offset + 1 + length]
        if s[0] == 0:
            s = s[1:]
        return r + s


def sasl_nist256p_sign(username, keyid, challenge):
    """
    Compute NIST256P signature over the given challenge data

    Private key to sign with is stored on device and never leaves it
    so this function interfaces with the device to compute signature
    on it.
    """
    if challenge == '+':
        username_bytes = username.encode('ascii')
        answer = username_bytes + b'|' + username_bytes
    else:
        data = base64.b64decode(challenge)
        with LedgerInterface() as ledger:
            answer = ledger.sign(username, keyid, data)
    return base64.b64encode(answer).decode('ascii')


def sasl_nist256p_pubkey(username, keyid):
    """
    Connect to a device and get a public key for a given identity
    """
    with LedgerInterface() as ledger:
        answer = ledger.pubkey(username, keyid)
    return base64.b64encode(answer).decode('ascii')


def main(args):
    """
    SASL DELEGATED protocol logic:
        - if called without arguments, return registered (supported)
          name of the mechanism (ecdsa_nist256p_challenge in this case);
        - if called with three arguments, assume it's username, key and
          base64-encoded challenge data and return the signature of the
          given data with the given key;
        - as a special case, when called with two arguments, return
          base64-encoded public key for registration purposes;
        - otherwise return empty string (shouldn't happen).
    """
    if len(args) == 1:
        print('ecdsa_nist256p_challenge')
    elif len(args) == 3:
        # hidden undocumented hacky hack for extracting public key
        username, keyid = args[1], args[2]
        print(sasl_nist256p_pubkey(username, keyid))
    elif len(args) == 4:
        username, keyid, challenge = args[1], args[2], args[3]
        print(sasl_nist256p_sign(username, keyid, challenge))
    else:
        print('')


if __name__ == '__main__':
    main(sys.argv)
