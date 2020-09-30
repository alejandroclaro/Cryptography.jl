#
# @description Implements the Identity (NULL) block cipher algorithm.
#
# @author Alejandro Claro (alejandro.claro@gmail.com)
#
# Copyright 2015 All rights reserved.
# Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.
#
export NullBlockCipher
export block_size, key_size, encrypt, decrypt

# @description Defines the null block-cipher data struture.
mutable struct NullBlockCipher <: BlockCipher
  block_size::UInt64
  key_size::UInt64

  # @description Initialize the null block-cipher.
  function NullBlockCipher()
    return new(16, 16)
  end

  # @description Initialize the null block-cipher.
  #
  # @param {Integer} block_size The cipher block size.
  # @param {Integer} key_size   The cipher key size.
  function NullBlockCipher(block_size::Integer, key_size::Integer)
    return new(block_size, key_size)
  end
end

# @description Gets the cipher block size.
#
# @param {NullBlockCipher} self The cipher data struture.
#
# @return {Integer} The block size in bytes.
function block_size(self::NullBlockCipher)
  return self.block_size
end

# @description Gets the cipher key size.
#
# @param {NullBlockCipher} self The cipher data struture.
#
# @return {Integer} The key size in bytes.
function key_size(self::NullBlockCipher)
  return self.key_size
end

# @description Simulates the encryption of the given plaintext block.
#
# @param {NullBlockCipher} self      The cipher data struture.
# @param {Vector{UInt8}}   plaintext The message to encrypt.
#
# @return {Vector{UInt8}} A copy of the given plaintext block.
function encrypt(self::NullBlockCipher, plaintext::Vector{UInt8})
  if length(plaintext) != block_size(self)
    throw(ArgumentError("Invalid input block length."))
  end

  return deepcopy(plaintext)
end

# @description Simulates the decryption of the given ciphertext block.
#
# @param {NullBlockCipher} self       The cipher data struture.
# @param {Vector{UInt8}}   ciphertext The message to decrypt.
#
# @return {Vector{UInt8}} A copy of the given ciphertext block.
function decrypt(self::NullBlockCipher, ciphertext::Vector{UInt8})
  if length(ciphertext) != block_size(self)
    throw(ArgumentError("Invalid input block length."))
  end

  return deepcopy(ciphertext)
end
