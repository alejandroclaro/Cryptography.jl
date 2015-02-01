#
# @@description Implements the CBC (Cipher-Block Chaining) multiblock cipher algorithms.
#
# @@author Alejandro Claro (alejandro.claro@gmail.com)
#
# Copyright 2015 All rights reserved.
# Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.
#
using ..Padders

export CBC
export block_size, key_size, iv_size, iv, reset!, encrypt_block!, encrypt_last_block!, decrypt_block!, decrypt_last_block!

#' @@description Defines the CBC cipher mode data struture.
type CBC <: MultiBlockCipher
  blockcipher::BlockCipher
  padder::PaddingAlgorithm
  iv::Vector{UInt8}

  #' @@description Initialize the CBC cipher with a random initialization vector.
  #'
  #' @@param {BlockCipher}      blockcipher The block cipher.
  #' @@param {PaddingAlgorithm} padder      The padding algorithm.
  function CBC(blockcipher::BlockCipher, padder::PaddingAlgorithm)
    # TODO: Generate random IV using cryptographic secure RNG.
    return new(blockcipher, padder, rand(UInt8, block_size(blockcipher)))
  end

  #' @@description Initialize the CBC cipher.
  #'
  #' @@param {BlockCipher}      blockcipher The block cipher.
  #' @@param {PaddingAlgorithm} padder      The padding algorithm.
  #' @@param {Vector{UInt8}}    iv          The initialization vector.
  function CBC(blockcipher::BlockCipher, padder::PaddingAlgorithm, iv::Vector{UInt8})
    if length(iv) != block_size(blockcipher)
      error("Invalid initialization vector length.")
    end

    return new(blockcipher, padder, iv)
  end
end

#' @@description Gets the cipher block size.
#'
#' @@param {CBC} self The cipher data struture.
#'
#' @@return {Integer} The block size in bytes.
function block_size(self::CBC)
  return block_size(self.blockcipher)
end

#' @@description Gets the cipher key size.
#'
#' @@param {CBC} self The cipher data struture.
#'
#' @@return {Integer} The key size in bytes.
function key_size(self::CBC)
  return key_size(self.blockcipher)
end

#' @@description Gets the cipher initialization vector size.
#'
#' @@param {CBC} self The cipher data struture.
#'
#' @@return {Integer} The initialization vector size in bytes.
function iv_size(self::CBC)
  return block_size(self.blockcipher)
end

#' @@description Gets the cipher initialization vector.
#'
#' @@param {CBC} self The cipher data struture.
#'
#' @@return {Vector{UInt8}} The initialization vector.
function iv(self::CBC)
  return self.iv
end

#' @@description Resets the state of the CBC data structure.
#'
#' @@param {CBC} self The hash algorithm.
#'
#' @@return The reference to the resetted cipher data structure.
function reset!(self::CBC)
  # TODO:
  return self
end

#' @@description Encrypts the given plaintext block.
#'
#' @@param {CBC}           self  The cipher data struture.
#' @@param {Vector{UInt8}} block The block from the message to encrypt.
#'
#' @@return {Vector{UInt8}} The resulting ciphertext block.
function encrypt_block!(self::CBC, block::Vector{UInt8})
  # TODO:
  return Array(UInt8, 0x8, 0x09)
end

#' @@description Encrypts the given last plaintext block.
#'
#' @@param {CBC}           self  The cipher data struture.
#' @@param {Vector{UInt8}} block The last block from the message to encrypt.
#'
#' @@return {Vector{UInt8}} The resulting last ciphertext blocks. This could be more than the size of a block.
function encrypt_last_block!(self::CBC, block::Vector{UInt8})
  # TODO:
  return Array(UInt8, 0xF, 0x0E)
end

#' @@description Decrypts the given ciphertext block.
#'
#' @@param {CBC}           self  The cipher data struture.
#' @@param {Vector{UInt8}} block The block from the message to decrypt.
#'
#' @@return {Vector{UInt8}} The resulting plaintext block.
function decrypt_block!(self::CBC, block::Vector{UInt8})
  # TODO:
  return Array(UInt8, 0x0C, 0x0D)
end

#' @@description Decrypts the given last ciphertext block.
#'
#' @@param {CBC}           self  The cipher data struture.
#' @@param {Vector{UInt8}} block The last block from the message to decrypt.
#'
#' @@return {Vector{UInt8}} The resulting last plaintext block. This could be less than the size of a block.
function decrypt_last_block!(self::CBC, block::Vector{UInt8})
  # TODO:
  return Array(UInt8, 0x0A, 0x0B)
end
