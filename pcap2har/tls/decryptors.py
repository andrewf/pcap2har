# Copyright 2012 Google Inc. All Rights Reserved.

'''
Decryptor objects for TLS.

Each has a decrypt(fragment) method that returns the decrypted data
and updates its internal state, if any. It also must handle any MAC
on the fragment.

Module also has a new function that takes an algorithm name (and optional
arguments and returns an appropriate decryptor, or NullDecryptor.
'''

import logging
from cStringIO import StringIO
import hashlib
import hmac

from Crypto.Cipher import AES


def Gen_P_hash(hashfn):
    '''
    Generate a P_hash function in style of the TLS spec.

    hashfn is a digest constructor, like hashlib.sha1.
    '''
    def HMAC_hash(secret, msg):
        return hmac.new(secret, msg, hashfn).digest()
    def P_hash(secret, seed, bytes_needed):
        A = seed  # A(0) in TLS spec
        output = StringIO()
        while output.tell() < bytes_needed:
            A = HMAC_hash(secret, A) # A(1) first, A(2), A(3) etc.
            output.write(HMAC_hash(secret, A + seed))
        return output.getvalue()[:bytes_needed]
    return P_hash


P_SHA1 = Gen_P_hash(hashlib.sha1)
P_MD5 = Gen_P_hash(hashlib.md5)
P_SHA256 = Gen_P_hash(hashlib.sha256)


def TLS1_PRF(secret, label, seed, bytes_needed):
    # divide by two, rounding up
    L_S1 = L_S2 = len(secret) / 2 + len(secret) % 2
    S1 = secret[:L_S1]
    S2 = secret[-L_S2:]
    md5_hash = P_MD5(S1, label + seed, bytes_needed)
    sha_hash = P_SHA1(S2, label + seed, bytes_needed)
    # there has GOT to be a better way to do this.
    return ''.join(
        chr(ord(s) ^ ord(m)) for s, m in zip(sha_hash, md5_hash))


def KeysFromMasterSecret(params):
    '''
    Given master_secret, client_random and server_random, get all the
    specific keys for the connection:

    Returns (strings):
    * server_read_MAC_secret
    * client_read_MAC_secret
    * server_read_key
    * client_read_key
    * server_read_IV
    * client_read_IV

    Note that in the spec, the first entry in each pair is called
    "client_write...", while here we call it "server_read...", since we're only
    interested in reading.
    '''
    mac_len = 20  #params.cipher_suite.mac_len
    key_len = 32  # AAAAA!
    iv_len = 16
    keyMaterial = TLS1_PRF(params.master_secret, "key expansion",
                           params.server_random + params.client_random,
                           2*mac_len + 2*key_len + 2*iv_len)
    pointer = 0
    outputs = []
    for length in (mac_len, mac_len, key_len, key_len, iv_len, iv_len):
        outputs.append(keyMaterial[pointer:pointer+length])
        pointer += length
    return tuple(outputs)

class Decryptor(object):

    def __init__(self, params, client_perspective):
        self.params = params
        self.client_perspective = client_perspective

    def decrypt(self, fragment):
        raise NotImplementedError


class StreamDecryptor(Decryptor):

    def decrypt(self, fragment):
        raise NotImplementedError

    def remove_mac(self, fragment):
        mac_size = self.params.cipher_suite.mac_size
        if mac_size != 0:
            return fragment[:-mac_size]
        return fragment


class NullDecryptor(StreamDecryptor):
    def decrypt(self, fragment):
        return self.remove_mac(fragment)


class BlockDecryptor(Decryptor):
    '''
    Base class for block cipher decryptors, handles generic block cipher stuff.

    Behaves differently for different TLS versions. Before 1.1, there was no
    explicit IV field in the GenericBlockCipher struct, and the residue from
    the previous decryption is used. For 1.1 and later, the IV is included in
    the fragment.

    Heck with it. Just pretend we're dealing with 1.1 or later.
    '''

    def separate_iv(self, fragment):
        '''
        Parse IV and encrypted data out of fragment and return them in a tuple.
        '''
        iv_size = self.params.cipher_suite.block_size
        return fragment[:iv_size], fragment[iv_size:]


class Aes256Cbc(BlockDecryptor):
    # for purposes of hacking, don't really use base class.

    def __init__(self, params, client_perspective):
        #print 'creating Aes256Cbc'
        Decryptor.__init__(self, params, client_perspective)
        # TLS1.0 specific logic
        if not params.master_secret:
            raise RuntimeError('missing master_secret')
        if not params.client_random:
            raise RuntimeError('missing client random')
        if not params.server_random:
            raise RuntimeError('missing server random')
        keys = KeysFromMasterSecret(params)
        if self.client_perspective:
            self.key = keys[3]
            self.iv = keys[5]
        else:
            self.key = keys[2]
            self.iv = keys[4]
        self.state = AES.new(
            self.key,
            AES.MODE_CBC,
            self.iv)

    def decrypt(self, fragment):
        #print 'decrypting AES_256_CBC'
        #iv, ciphertext = self.separate_iv(fragment)
        if len(fragment) % self.params.cipher_suite.block_size != 0:
            # invalid length
            raise RuntimeError("Ciphertext is wrong length for block cipher "
              "(%d)" % len(ciphertext))
        #algo = Crypto.Cipher.AES.new(iv, Crypto.Cipher.AES.MODE_CBC)
        #return algo.decrypt(ciphertext)
        plaintext = self.state.decrypt(fragment)
        # plaintext now contains the record, a mac, and padding
        padding_amount = ord(plaintext[-1])  # plus 1, actually
        plaintext = plaintext[:-(self.params.cipher_suite.mac_size + padding_amount +
                           1)]
        #print '  decrypted stuff: %r..%r' % (plaintext[:10], plaintext[-10:])
        return plaintext



ALGORITHMS = {
    'NULL': NullDecryptor,
    'AES_256_CBC': Aes256Cbc,
}

def new(params, client_perspective):
    name = params.cipher_suite.encoding
    if name not in ALGORITHMS:
        logging.warning('Unknown algo %r, returning NullDecryptor' % name)
    cls = ALGORITHMS.get(name, NullDecryptor)
    return cls(params, client_perspective)
