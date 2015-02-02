#
# @description Unit tests for PKCS#7 padding method.
#
# @author Alejandro Claro (alejandro.claro@gmail.com)
#
# Copyright 2015 All rights reserved.
# Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.
#

padder = Pkcs7Padder()

@test pad(padder, [ 0x0A, 0x0B ], 8) == [ 0x0A, 0x0B, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06 ]
@test pad(padder, [ 0x0A, 0x0B ], 2) == [ 0x0A, 0x0B, 0x02, 0x02 ]

@test unpad(padder, [ 0x0A, 0x0B, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06 ]) == [ 0x0A, 0x0B ]
@test unpad(padder, [ 0x02, 0x02 ]) == []

@test_throws PaddingError unpad(padder, [ 0xFF, 0x00 ])
@test_throws PaddingError unpad(padder, [ 0x03, 0x03 ])
@test_throws PaddingError unpad(padder, [ 0x0A, 0x0B, 0x03, 0x03 ])
@test_throws PaddingError unpad(padder, [ 0x0A, 0x0B, 0x0F, 0x02 ])
