#
# @@description Unit test for MD5 hash algorithm.
#
# @@author Alejandro Claro (alejandro.claro@gmail.com)
#
# Copyright 2015 All rights reserved.
# Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.
#
using Cryptography.Hashers

@test MD5_DIGEST_SIZE    == 16
@test digest_size(MD5()) == 16

hasher = MD5()
update!(hasher, "")
@test digest(hasher) == [ 0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04, 0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e ]

hasher = MD5()
update!(hasher, "abc")
reset!(hasher)
update!(hasher, "")
@test hexdigest(hasher) == "d41d8cd98f00b204e9800998ecf8427e"

hasher = MD5()
update!(hasher, [ 0x00, 0x01, 0x02 ])
@test hexdigest(hasher) == "b95f67f61ebb03619622d798f45fc2d3"
update!(hasher, [ 0x03, 0x04, 0x05 ])
@test hexdigest(hasher) == "d15ae53931880fd7b724dd7888b4b4ed"

@test digest(MD5(), "a")                 == [ 0x0c, 0xc1, 0x75, 0xb9, 0xc0, 0xf1, 0xb6, 0xa8, 0x31, 0xc3, 0x99, 0xe2, 0x69, 0x77, 0x26, 0x61 ]
@test hexdigest(MD5(), "abc")            == "900150983cd24fb0d6963f7d28e17f72"
@test hexdigest(MD5(), "message digest") == "f96b697d7cb7938d525a2f31aaf161d0"
@test hexdigest(MD5(), "abcdefghijklmnopqrstuvwxyz") == "c3fcd3d76192e4007dfb496cca67e13b"
@test hexdigest(MD5(), "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") == "d174ab98d277d9f5a5611c2c9f419d9f"
