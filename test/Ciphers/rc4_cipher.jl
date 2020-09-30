#
# @description Unit tests for RC4 stream-cipher.
#
# @author Alejandro Claro (alejandro.claro@gmail.com)
#
# Copyright 2017 All rights reserved.
# Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.
#
@testset "RC4 cipher tests" begin
  cipher = Rc4Cipher([ 0x01, 0x02, 0x03, 0x04, 0x05 ])

  @test key_size(cipher) == 5

  @test_throws ArgumentError Rc4Cipher(UInt8[])
  @test_throws ArgumentError Rc4Cipher(zeros(UInt8, 33))

  @test encrypt!(cipher, [ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ]) == UInt8[ 0xb2, 0x39, 0x63, 0x05, 0xf0, 0x3d, 0xc0, 0x27 ]

  reset!(cipher)

  @test decrypt!(cipher, UInt8[ 0xb2, 0x39, 0x63, 0x05, 0xf0, 0x3d, 0xc0, 0x27 ]) == [ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ]
end

