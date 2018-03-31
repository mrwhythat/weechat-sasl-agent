#! /usr/bin/env python

#
# WeeChat SASL agent for DELEGATED SASL mechanism
#

import sys
import base64

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_private_key


def nist256p_challenge(username, keyfile, challenge):
    """
    Compute NIST256P signature over the given challenge data

    Assume 'challenge' data is base64-encoded string and 'keyfile'
    is a base64-encoded private key to be used for signing.
    """
    if challenge == '+':
        username_bytes = username.encode('ascii')
        answer = username_bytes + b'|' + username_bytes
    else:
        with open(keyfile, 'r') as f:
            backend = default_backend()
            data = base64.b64decode(challenge)
            keydata = f.read().encode('ascii')
            private_key = load_pem_private_key(keydata, None, backend)
            answer = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    return base64.b64encode(answer).decode('ascii')


def main(args):
    """
    SASL DELEGATED protocol logic:
        - if called without arguments, return registered (supported)
          name of the mechanism (ecdsa_nist256p_challenge in this case);
        - if called with three arguments, assume it's username, key and
          base64-encoded challenge data and return the signature of the
          given data with the given key;
        - otherwise return empty string (shouldn't happen).
    """
    if len(args) == 1:
        print('ecdsa_nist256p_challenge')
    elif len(args) == 4:
        username, keyfile, challenge = args[1], args[2], args[3]
        print(nist256p_challenge(username, keyfile, challenge))
    else:
        print('')


if __name__ == '__main__':
    main(sys.argv)
