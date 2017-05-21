#
# @description Unit tests for DES block-cipher.
#
# @author Alejandro Claro (alejandro.claro@gmail.com)
#
# Copyright 2017 All rights reserved.
# Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.
#

cipher = TripleDesCipher([ 0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1 ])

@test block_size(cipher) == 8
@test key_size(cipher)   == 8

@test_throws ArgumentError TripleDesCipher(UInt8[])
@test_throws ArgumentError TripleDesCipher([ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 ])

@test_throws ArgumentError encrypt(cipher, UInt8[])
@test_throws ArgumentError encrypt(cipher, [ 0x05, 0x06 ])

@test_throws ArgumentError decrypt(cipher, UInt8[])
@test_throws ArgumentError decrypt(cipher, [ 0x05, 0x06 ])
