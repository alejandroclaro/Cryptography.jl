#
# @@description Defines the multiblock-cipher abstract type and the helper methods that act on this abstract type.
#
# @@author Alejandro Claro (alejandro.claro@gmail.com)
#
# Copyright 2015 All rights reserved.
# Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.
#
export MultiBlockCipher
export encryptor, decryptor, encrypt, decrypt

#' @@description Defines the multiblock-cipher abstract type. A multiblock-cipher is an algorithm that uses a block
#' cipher repeatedly to securely transform amounts of data larger than a block.
abstract MultiBlockCipher

#' @@description Returns the encryption function linked to the given multiblock-cipher.
#'
#' @@param {MultiBlockCipher} self The cipher data struture.
#'
#' @@return {Function} A function that only takes one {Vector{Uint8}} argument.
function encryptor(self::MultiBlockCipher)
  return plaintext -> encrypt(self, plaintext)
end

#' @@description Returns the decryption function linked to the given multiblock-cipher.
#'
#' @@param {MultiBlockCipher} self The cipher data struture.
#'
#' @@return {Function} A function that only takes one {Vector{Uint8}} argument.
function decryptor(self::MultiBlockCipher)
  return ciphertext -> decrypt(self, ciphertext)
end

#' @@description Encrypts the given plaintext with the key set at initialization.
#'
#' @@param {MultiBlockCipher} self      The cipher data struture.
#' @@param {AbstractString}   plaintext The message to encrypt.
#'
#' @@return {Vector{Uint8}} The resulting ciphertext.
function encrypt(self::MultiBlockCipher, plaintext::AbstractString)
  return encrypt(self, convert(Array{UInt8}, plaintext))
end

#' @@description Encrypts the given plaintext with the key set at initialization.
#'
#' @@param {MultiBlockCipher} self      The cipher data struture.
#' @@param {Vector{Uint8}}    plaintext The message to encrypt.
#'
#' @@return {Vector{Uint8}} The resulting ciphertext.
function encrypt(self::MultiBlockCipher, plaintext::Vector{Uint8})
return process(self, encrypt_block!, plaintext)
end

#' @@description Decrypts the given ciphertext with the key set at initialization.
#'
#' @@param {MultiBlockCipher} sself       The cipher data struture.
#' @@param {Vector{Uint8}}    ciphertext The message to decrypt.
#'
#' @@return {Vector{Uint8}} The resulting plaintext.
function decrypt(self::MultiBlockCipher, ciphertext::Vector{Uint8})
  return process(self, decrypt_block!, ciphertext)
end

#' @@description Encrypts or decrypts the given data with the key set at initialization.
#'
#' @@param {MultiBlockCipher} self          The cipher data struture.
#' @@param {MultiBlockCipher} process_block The cipher operation.
#' @@param {Vector{Uint8}}    data          The message to process.
#'
#' @@return {Vector{Uint8}} The processed data.
function process(self::MultiBlockCipher, process_block::Function, data::Vector{Uint8})
  algorithm            = deepcopy(self)
  step                 = block_size(algorithm)
  len                  = length(data)
  index                = 1
  result::Array{Uint8} = []

  reset!(algorithm)

  while (index + step) <= len
    last   = index + step
    result = vcat(result, process_block(algorithm, data[index:last]))
    index += step
  end

  result = vcat(result, process_block(algorithm, data[index:end]))
end
