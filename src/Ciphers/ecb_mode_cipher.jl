#
# @description Implements the ECB (Electronic Codebook) mode of operation algorithm.
#
# @author Alejandro Claro (alejandro.claro@gmail.com)
#
# Copyright 2017 All rights reserved.
# Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.
#
export EcbModeCipher
export block_size, key_size, reset!, encrypt_next_blocks!, encrypt_last_block!, decrypt_next_blocks!, decrypt_last_block!

# @description Defines the CBC cipher mode data struture.
struct EcbModeCipher <: MultiBlockCipher
  block_cipher::BlockCipher
  padder::PaddingMethod
  partial_block::Vector{UInt8}

  # @description Initialize the ECB cipher.
  #
  # @param {BlockCipher}   block_cipher The block cipher.
  # @param {PaddingMethod} padder       The padding method.
  function CbcModeCipher(block_cipher::BlockCipher, padder::PaddingMethod)
    return new(block_cipher, padder, UInt8[]))
  end
end

# @description Gets the cipher block size.
#
# @param {EcbModeCipher} self The cipher data struture.
#
# @return {Integer} The block size in bytes.
function block_size(self::EcbModeCipher)
  return block_size(self.block_cipher)
end

# @description Gets the cipher key size.
#
# @param {EcbModeCipher} self The cipher data struture.
#
# @return {Integer} The key size in bytes.
function key_size(self::EcbModeCipher)
  return key_size(self.block_cipher)
end

# @description Resets the state of the CBC data structure.
#
# @param {EcbModeCipher} self The hash algorithm.
#
# @return The reference to the resetted cipher data structure.
function reset!(self::EcbModeCipher)
  empty!(self.partial_block)
  return self
end

# @description Continues a multiple-part encryption operation processing another data part.
#
# @param {EcbModeCipher} self The cipher data struture.
# @param {Vector{UInt8}} data The message part to encrypt.
#
# @return {Vector{UInt8}} The resulting ciphertext blocks. It can be a empty vector if the input data is too short to
# result in a new block.
function encrypt_next_blocks!(self::EcbModeCipher, data::Vector{UInt8})
  data   = vcat(self.partial_block, data)
  step   = block_size(self)
  len    = length(data)
  result = UInt8[]

  for i in 1 : step : (len - 1)
    ciphertext = encrypt(self.block_cipher, data[i : (i + step - 1)])
    append!(result, ciphertext)
  end

  empty!(self.partial_block)
  append!(self.partial_block, data[(end - mod(len, step) + 1) : end])

  return result
end

# @description Encrypts the given last plaintext block.
#
# @param {EcbModeCipher} self  The cipher data struture.
# @param {Vector{UInt8}} block The last block from the message to encrypt.
#
# @return {Vector{UInt8}} The resulting last ciphertext blocks. This could be more than the size of a block.
function encrypt_last_block!(self::EcbModeCipher, block::Vector{UInt8})
  result       = encrypt_next_blocks!(self, block)
  padded_block = pad(self.padder, self.partial_block, block_size(self))
  ciphertext   = encrypt(self.block_cipher, padded_block)

  append!(result, ciphertext)
  reset!(self)

  return result
end

# @description Continues a multiple-part decryption operation processing another data part.
#
# @param {EcbModeCipher} self  The cipher data struture.
# @param {Vector{UInt8}} data  The message part to decrypt.
#
# @return {Vector{UInt8}} The resulting plaintext blocks. It can be a empty vector if the input data is too short to
# result in a new block.
function decrypt_next_blocks!(self::EcbModeCipher, data::Vector{UInt8})
  data   = vcat(self.partial_block, data)
  step   = block_size(self)
  len    = length(data)
  result = UInt8[]

  for i in 1 : step : (len - 1)
    ciphertext = data[i : (i + step - 1)]
    plaintext  = decrypt(self.block_cipher, ciphertext)
    append!(result, plaintext)
  end

  empty!(self.partial_block)
  append!(self.partial_block, data[(end - mod(len, step) + 1) : end])

  return result
end

# @description Decrypts the given last ciphertext block.
#
# @param {EcbModeCipher} self  The cipher data struture.
# @param {Vector{UInt8}} block The last block from the message to decrypt.
#
# @return {Vector{UInt8}} The resulting last plaintext block. This could be less than the size of a block.
function decrypt_last_block!(self::EcbModeCipher, block::Vector{UInt8})
  result = decrypt_next_blocks!(self, block)

  if !isempty(self.partial_block)
    throw(BlockSizeError())
  end

  result = unpad(self.padder, result)
  reset!(self)

  return result
end
