#
# @description Implements the CBC (Cipher-Block Chaining) mode of operation algorithm.
#
# @author Alejandro Claro (alejandro.claro@gmail.com)
#
# Copyright 2015 All rights reserved.
# Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.
#
export CbcModeCipher
export block_size, key_size, iv_size, iv, reset!, encrypt_next_blocks!, encrypt_last_block!, decrypt_next_blocks!, decrypt_last_block!

# @description Defines the CBC cipher mode data struture.
struct CbcModeCipher <: MultiBlockCipher
  block_cipher::BlockCipher
  padder::PaddingMethod
  iv::Vector{UInt8}

  # Operation state.
  previous_block::Vector{UInt8}
  partial_block::Vector{UInt8}

  # @description Initialize the CBC cipher with a random initialization vector.
  #
  # @param {BlockCipher}   block_cipher The block cipher.
  # @param {PaddingMethod} padder       The padding method.
  function CbcModeCipher(block_cipher::BlockCipher, padder::PaddingMethod)
    # TODO: Generate random IV using cryptographic secure RNG.
    iv = rand(UInt8, block_size(block_cipher))
    return reset!(new(block_cipher, padder, iv, UInt8[], UInt8[]))
  end

  # @description Initialize the CBC cipher.
  #
  # @param {BlockCipher}   block_cipher The block cipher.
  # @param {PaddingMethod} padder       The padding method.
  # @param {Vector{UInt8}} iv           The initialization vector.
  function CbcModeCipher(block_cipher::BlockCipher, padder::PaddingMethod, iv::Vector{UInt8})
    if length(iv) != block_size(block_cipher)
      throw(ArgumentError("Invalid initialization vector length. $(length(iv) * 8) bits recived, but $(block_size(block_cipher) * 8) bits expected."))
    end

    return reset!(new(block_cipher, padder, iv, UInt8[], UInt8[]))
  end
end

# @description Gets the cipher block size.
#
# @param {CbcModeCipher} self The cipher data struture.
#
# @return {Integer} The block size in bytes.
function block_size(self::CbcModeCipher)
  return block_size(self.block_cipher)
end

# @description Gets the cipher key size.
#
# @param {CbcModeCipher} self The cipher data struture.
#
# @return {Integer} The key size in bytes.
function key_size(self::CbcModeCipher)
  return key_size(self.block_cipher)
end

# @description Gets the cipher initialization vector size.
#
# @param {CbcModeCipher} self The cipher data struture.
#
# @return {Integer} The initialization vector size in bytes.
function iv_size(self::CbcModeCipher)
  return block_size(self.block_cipher)
end

# @description Gets the cipher initialization vector.
#
# @param {CbcModeCipher} self The cipher data struture.
#
# @return {Vector{UInt8}} The initialization vector.
function iv(self::CbcModeCipher)
  return self.iv
end

# @description Resets the state of the CBC data structure.
#
# @param {CbcModeCipher} self The hash algorithm.
#
# @return The reference to the resetted cipher data structure.
function reset!(self::CbcModeCipher)
  empty!(self.partial_block)

  resize!(self.previous_block, block_size(self))
  map!(x -> x, self.previous_block, self.iv)

  return self
end

# @description Continues a multiple-part encryption operation processing another data part.
#
# @param {CbcModeCipher} self The cipher data struture.
# @param {Vector{UInt8}} data The message part to encrypt.
#
# @return {Vector{UInt8}} The resulting ciphertext blocks. It can be a empty vector if the input data is too short to
# result in a new block.
function encrypt_next_blocks!(self::CbcModeCipher, data::Vector{UInt8})
  data   = vcat(self.partial_block, data)
  step   = block_size(self)
  len    = length(data)
  result = UInt8[]

  for i in 1 : step : (len - 1)
    xor        = map((x,y) -> x ⊻ y, self.previous_block, data[i : (i + step - 1)])
    ciphertext = encrypt(self.block_cipher, xor)

    map!(x -> x, self.previous_block, ciphertext)
    append!(result, ciphertext)
  end

  empty!(self.partial_block)
  append!(self.partial_block, data[(end - (len % step) + 1) : end])

  return result
end

# @description Encrypts the given last plaintext block.
#
# @param {CbcModeCipher} self  The cipher data struture.
# @param {Vector{UInt8}} block The last block from the message to encrypt.
#
# @return {Vector{UInt8}} The resulting last ciphertext blocks. This could be more than the size of a block.
function encrypt_last_block!(self::CbcModeCipher, block::Vector{UInt8})
  result = encrypt_next_blocks!(self, block)

  padded_block = pad(self.padder, self.partial_block, block_size(self))
  xor          = map((x,y) -> x ⊻ y, self.previous_block, padded_block)
  ciphertext   = encrypt(self.block_cipher, xor)

  append!(result, ciphertext)
  reset!(self)

  return result
end

# @description Continues a multiple-part decryption operation processing another data part.
#
# @param {CbcModeCipher} self  The cipher data struture.
# @param {Vector{UInt8}} data  The message part to decrypt.
#
# @return {Vector{UInt8}} The resulting plaintext blocks. It can be a empty vector if the input data is too short to
# result in a new block.
function decrypt_next_blocks!(self::CbcModeCipher, data::Vector{UInt8})
  data   = vcat(self.partial_block, data)
  step   = block_size(self)
  len    = length(data)
  result = UInt8[]

  for i in 1 : step : (len - 1)
    ciphertext = data[i : (i + step - 1)]
    plaintext  = decrypt(self.block_cipher, ciphertext)
    xor        = map((x,y) -> x ⊻ y, self.previous_block, plaintext)

    map!(x -> x, self.previous_block, ciphertext)
    append!(result, xor)
  end

  empty!(self.partial_block)
  append!(self.partial_block, data[(end - (len % step) + 1) : end])

  return result
end

# @description Decrypts the given last ciphertext block.
#
# @param {CbcModeCipher} self  The cipher data struture.
# @param {Vector{UInt8}} block The last block from the message to decrypt.
#
# @return {Vector{UInt8}} The resulting last plaintext block. This could be less than the size of a block.
function decrypt_last_block!(self::CbcModeCipher, block::Vector{UInt8})
  result = decrypt_next_blocks!(self, block)

  if isempty(self.partial_block) == false
    throw(BlockSizeError())
  end

  result = unpad(self.padder, result)
  reset!(self)

  return result
end
