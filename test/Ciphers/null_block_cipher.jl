#
# @description Unit tests for null (identity) block-cipher.
#
# @author Alejandro Claro (alejandro.claro@gmail.com)
#
# Copyright 2015 All rights reserved.
# Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.
#
@testset "Null cipher tests" begin
  cipher = NullBlockCipher()

  @test block_size(cipher) == 16
  @test key_size(cipher)   == 16

  cipher = NullBlockCipher(4, 24)

  @test block_size(cipher) == 4
  @test key_size(cipher)   == 24

  @test encrypt(cipher, [ 0x01, 0x02, 0x03, 0x04 ]) == [ 0x01, 0x02, 0x03, 0x04 ]
  @test encrypt(cipher, [ 0x05, 0x06, 0x07, 0x08 ]) == [ 0x05, 0x06, 0x07, 0x08 ]

  @test_throws ArgumentError encrypt(cipher, UInt8[])
  @test_throws ArgumentError encrypt(cipher, [ 0x05, 0x06 ])
  @test_throws ArgumentError encrypt(cipher, [ 0x05, 0x06, 0x07, 0x08, 0x09 ])

  @test decrypt(cipher, [ 0x01, 0x02, 0x03, 0x04 ]) == [ 0x01, 0x02, 0x03, 0x04 ]
  @test decrypt(cipher, [ 0x05, 0x06, 0x07, 0x08 ]) == [ 0x05, 0x06, 0x07, 0x08 ]

  @test_throws ArgumentError decrypt(cipher, UInt8[])
  @test_throws ArgumentError decrypt(cipher, [ 0x05, 0x06 ])
  @test_throws ArgumentError decrypt(cipher, [ 0x05, 0x06, 0x07, 0x08, 0x09 ])
end

