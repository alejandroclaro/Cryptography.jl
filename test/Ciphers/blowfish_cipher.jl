#
# @description Unit tests for Blowfish block-cipher.
#
# @author Alejandro Claro (alejandro.claro@gmail.com)
#
# Copyright 2017 All rights reserved.
# Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.
#

cipher = BlowfishCipher([ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ])

@test block_size(cipher) == 8
@test key_size(cipher)   == 8

@test_throws ArgumentError BlowfishCipher(UInt8[])
@test_throws ArgumentError encrypt(cipher, UInt8[])
@test_throws ArgumentError encrypt(cipher, [ 0x05, 0x06 ])
@test_throws ArgumentError decrypt(cipher, UInt8[])
@test_throws ArgumentError decrypt(cipher, [ 0x05, 0x06 ])

@test encrypt(cipher, [ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ]) == UInt8[ 0x4E, 0xF9, 0x97, 0x45, 0x61, 0x98, 0xDD, 0x78 ]
@test decrypt(cipher, UInt8[ 0x4E, 0xF9, 0x97, 0x45, 0x61, 0x98, 0xDD, 0x78 ]) == [ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ]
