#
# @@description Unit test for MD5 hash algorithm.
#
# @@author Alejandro Claro (alejandro.claro@gmail.com)
#
# Copyright 2015 All rights reserved.
# Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.
#
using Cryptography.Hashers.MD5

@test MD5_DIGEST_SIZE    == 16
@test digest_size(MD5()) == 16

hasher = MD5()
update!(hasher, "")
@test digest(hasher) == "d41d8cd98f00b204e9800998ecf8427e"

hasher = MD5()
update!(hasher, "abc")
reset!(hasher)
update!(hasher, "")
@test digest(hasher) == "d41d8cd98f00b204e9800998ecf8427e"

hasher = MD5()
update!(hasher, "abc")
@test digest(hasher) == "900150983cd24fb0d6963f7d28e17f72"
update!(hasher, "def")
@test digest(hasher) == "900150983cd24fb0d6963f7d28e17f72"

@test digest(MD5(), "a")              == "0cc175b9c0f1b6a831c399e269772661"
@test digest(MD5(), "abc")            == "900150983cd24fb0d6963f7d28e17f72"
@test digest(MD5(), "message digest") == "f96b697d7cb7938d525a2f31aaf161d0"
@test digest(MD5(), "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") == "d174ab98d277d9f5a5611c2c9f419d9f"
