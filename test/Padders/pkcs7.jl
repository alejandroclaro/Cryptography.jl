#
# @@description Unit test for PKCS#7 padding algorithm.
#
# @@author Alejandro Claro (alejandro.claro@gmail.com)
#
# Copyright 2015 All rights reserved.
# Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.
#
using Cryptography.Padders

padder = Pkcs7()

@test pad(padder, [ 0x0A, 0x0B ], 8) == [ 0x0A, 0x0B, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06 ]
@test unpad(padder, [ 0x0A, 0x0B, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06 ]) == [ 0x0A, 0x0B ]
