#
# @description Implements the Feistel block cipher algorithms.
#
# @author Alejandro Claro (alejandro.claro@gmail.com)
#
# Copyright 2017 All rights reserved.
# Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.
#
export FeistelCipher
export block_size, key_size, encrypt, decrypt

# @description Defines the DES cipher data struture.
#
# f          The round function f(R, key).
# keys       The set of keys.The number of keys defines the number of iterations.
# key_size   The size of the key from input keys where derived.
# block_size The round function input block size.
immutable FeistelCipher <: BlockCipher
  f::Function
  keys::Vector{Vector{UInt8}}
  key_size::UInt64
  block_size::UInt64
end

# @description Gets the cipher block size.
#
# @param {FeistelCipher} self The cipher data struture.
#
# @return {Integer} The block size in bytes.
function block_size(self::FeistelCipher)
  return self.block_size
end

# @description Gets the cipher key size.
#
# @param {DesCipher} self The cipher data struture.
#
# @return {Integer} The key size in bytes.
function key_size(self::FeistelCipher)
  return self.key_size
end

# @description Encrypts the given plaintext block with the key set at initialization.
#
# @param {FeistelCipher}     self      The cipher data struture.
# @param {Vector{UInt8}} plaintext The message to encrypt.
#
# @return {Vector{UInt8}} The resulting ciphertext block.
function encrypt(self::FeistelCipher, plaintext::Vector{UInt8})
  if length(plaintext) != block_size(self)
    throw(ArgumentError("Invalid input plaintext length."))
  end

  return compute_feistel_network(plaintext, self.keys, self.f);
end

# @description Decrypts the given ciphertext block with the key set at initialization.
#
# @param {FeistelCipher}     self       The cipher data struture.
# @param {Vector{UInt8}} ciphertext The message to decrypt.
#
# @return {Vector{UInt8}} The resulting plaintext block.
function decrypt(self::FeistelCipher, ciphertext::Vector{UInt8})
  if length(ciphertext) != block_size(self)
    throw(ArgumentError("Invalid input ciphertext length."))
  end

  return compute_feistel_network(ciphertext, reverse(self.keys), self.f);
end

# PRIVATE IMPLEMENTATION #######################################################

# @description Computes the Feistel network.
#
# @param {Vector{UInt8}}         block The block to transform.
# @param {Vector{Vector{UInt8}}} keys  The set of keys.
# @param {Function}             step   The round function f(R, key).
#
# @return {Vector{UInt8}} The Feistel network result.
function compute_feistel_network(block::Vector{UInt8}, keys::Vector{Vector{UInt8}}, round_function::Function)
  block = unpack_bits(block)
  half  = div(length(block), 2)
  ln    = block[1 : half]
  rn    = block[(half + 1) : end]

  for i in 1 : length(keys)
    r0 = copy(rn)
    f  = round_function(rn, keys[i])
    rn = map($, ln, f)
    ln = r0
  end

  return pack_bits(vcat(rn, ln))
end
