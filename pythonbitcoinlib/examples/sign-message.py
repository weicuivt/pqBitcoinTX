#!/usr/bin/env python3
#
# Copyright (C) 2013-2015 The python-bitcoinlib developers
#
# This file is part of python-bitcoinlib.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of python-bitcoinlib, including this file, may be copied, modified,
# propagated, or distributed except according to the terms contained in the
# LICENSE file.

from __future__ import absolute_import, division, print_function, unicode_literals
import hashlib
from bitcoin.wallet import CBitcoinSecret, P2PKHBitcoinAddress
from bitcoin.signmessage import BitcoinMessage, VerifyMessage, SignMessage

def sign_message(key, msg):
    secret = CBitcoinSecret(key)
    message = BitcoinMessage(msg)
    return SignMessage(secret, message)

def print_default(signature, key=None, msg=None):
    print(signature.decode('ascii'))

def print_verbose(signature, key, msg):
    secret = CBitcoinSecret(key)
    address = P2PKHBitcoinAddress.from_pubkey(secret.pub)
    message = BitcoinMessage(msg)
    print('Address: %s' % address)
    print('Message: %s' % msg)
    print('Signature: %s' % signature)
    print('Verified: %s' % VerifyMessage(address, message, signature))
    print('\nTo verify using bitcoin core:')
    print('\n`bitcoin-cli verifymessage %s \'%s\' \'%s\'`\n' % (address, signature.decode('ascii'), msg))

def parser():
    import argparse
    parser = argparse.ArgumentParser(
        description='Sign a message with a private key.',
        epilog='Security warning: arguments may be visible to other users on the same host.')
    parser.add_argument(
        '-v', '--verbose', dest='print_result',
        action='store_const', const=print_verbose, default=print_default,
        help='verbose output')
    parser.add_argument(
        '-k', '--key',
        required=True,
        help='private key in base58 encoding')
    parser.add_argument(
        '-m', '--msg',
        required=True,
        help='message to sign')
    return parser



if __name__ == '__main__':
    args = parser().parse_args()
    # unsigned = "0100000001416e9b4555180aaa0c417067a46607bc58c96f0131b2f41f7d0fb665eab03a7e000000001976a91499b1ebcfc11a13df5161aba8160460fe1601d54188acffffffff01204e0000000000001976a914e81d742e2c3c7acd4c29de090fc2c4d4120b2bf888ac0000000001000000"
    # txhash = hashlib.sha256(hashlib.sha256(unsigned.decode('hex')).digest()).digest()
    # privkey = '3cd0560f5b27591916c643a0b7aa69d03839380a738d2e912990dcc573715d2c'
    # signingkey = ecdsa.SigningKey.from_string(privkey.decode('hex'), curve=ecdsa.SECP256k1)
    # signature = sign_message(args.key, args.msg)

    try:
        signature = sign_message(args.key, args.msg)
    except Exception as error:
        print('%s: %s' % (error.__class__.__name__, str(error)))
        exit(1)
    else:
        args.print_result(signature, args.key, args.msg)
