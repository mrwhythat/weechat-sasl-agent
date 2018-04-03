#! /usr/bin/env python

#
# WeeChat SASL agent for DELEGATED SASL mechanism based on Ledger Nano S
# hardware cryptocurrency wallet
#

import sys
import base64

from libagent.device.ledger import LedgerNanoS as Device
# from libagent.device.fake_device import FakeDevice as Device
from libagent.device.interface import Identity


def ledger_challenge(username, keyid, challenge):
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
        identity = Identity('irc://{}@{}'.format(username, keyid), 'NIST256P')
        device = Device()
        device.connect()
        answer = device.sign(identity, data)
    return base64.b64encode(answer).decode('ascii')


def ledger_pubkey(username, keyid):
    """
    Connect to a device and get a public key for a given identity
    """
    identity = Identity('irc://{}@{}'.format(username, keyid), 'NIST256P')
    device = Device()
    device.connect()
    return base64.b64encode(device.pubkey(identity)).decode('ascii')


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
        print(ledger_pubkey(username, keyid))
    elif len(args) == 4:
        username, keyid, challenge = args[1], args[2], args[3]
        print(ledger_challenge(username, keyid, challenge))
    else:
        print('')


if __name__ == '__main__':
    main(sys.argv)
