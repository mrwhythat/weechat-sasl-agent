#! /usr/bin/env python

#
# WeeChat SASL agent for DELEGATED SASL mechanism based on Ledger Nano S
# hardware cryptocurrency wallet
#

import sys
import base64

# from libagent.device.fake_device import FakeDevice as Device
from ledgerblue.comm import getDongle


class LedgerInterface:
    def __init__(self):
        self.conn = None

    def __enter__(self):
        self.conn = getDongle()
        return self

    def __exit__(self):
        self.conn.close()

    def __identity(self, username, keyid):
        pass

    def pubkey(self, username, keyid):
        pass

    def sign(self, identity, challenge):
        pass


def identity(username, keyid):
    """Expand username and keyid into key path for Ledger dongle."""
    pass


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
        return ledger.pubkey(username, keyid)


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
