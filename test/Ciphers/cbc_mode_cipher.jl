#
# @description Unit tests for CBC mode of operation multi-block cipher.
#
# @author Alejandro Claro (alejandro.claro@gmail.com)
#
# Copyright 2015 All rights reserved.
# Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.
#
@testset "CBC mode cipher tests" begin
  # Test wrong IV lenght.
  @test_throws ArgumentError CbcModeCipher(NullBlockCipher(2, 2), Pkcs7Padder(), [ 0x00, 0x00, 0x00 ])
  @test_throws ArgumentError CbcModeCipher(NullBlockCipher(2, 2), Pkcs7Padder(), UInt8[])

  # Test accessors.
  cipher = CbcModeCipher(NullBlockCipher(2, 4), Pkcs7Padder(), [ 0x00, 0x00 ])

  @test block_size(cipher) == 2
  @test key_size(cipher)   == 4
  @test iv(cipher)         == [ 0x00, 0x00 ]

  # Test low-level functions.
  cipher = CbcModeCipher(NullBlockCipher(2, 4), Pkcs7Padder(), [ 0x00, 0x00 ])

  @test cipher.previous_block == [ 0x00, 0x00 ]
  @test cipher.partial_block  == []

  @test encrypt_next_blocks!(cipher, [ 0x01, 0x02, 0x03 ]) == [ 0x01, 0x02 ]

  @test cipher.previous_block == [ 0x01, 0x02 ]
  @test cipher.partial_block  == [ 0x03 ]

  @test encrypt_last_block!(cipher, UInt8[]) == [ 0x02, 0x03 ]

  @test cipher.previous_block == [ 0x00, 0x00 ]
  @test cipher.partial_block  == []

  @test decrypt_next_blocks!(cipher, [ 0x01, 0x02, 0x02 ]) == [ 0x01, 0x02 ]

  @test cipher.previous_block == [ 0x01, 0x02 ]
  @test cipher.partial_block  == [ 0x02 ]

  @test decrypt_last_block!(cipher, [ 0x03 ]) == [ 0x03 ]

  @test cipher.previous_block == [ 0x00, 0x00 ]
  @test cipher.partial_block  == []

  # Test high-level functions.
  cipher = CbcModeCipher(NullBlockCipher(2, 4), Pkcs7Padder(), [ 0x00, 0x00 ])

  @test encrypt(cipher, [ 0x01, 0x02, 0x03 ]) == [ 0x01, 0x02, 0x02, 0x03 ]
  @test encrypt(cipher, "\x01\x02\x03") == [ 0x01, 0x02, 0x02, 0x03 ]

  @test decrypt(cipher, [ 0x01, 0x02, 0x02, 0x03 ]) == [ 0x01, 0x02, 0x03 ]
end

