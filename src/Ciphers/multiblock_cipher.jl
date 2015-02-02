#
# @description Defines the multiblock-cipher abstract type and the helper methods that act on this abstract type.
#
# @author Alejandro Claro (alejandro.claro@gmail.com)
#
# Copyright 2015 All rights reserved.
# Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.
#
export MultiBlockCipher
export encrypt, decrypt

# @description Defines the multiblock-cipher abstract type. A multiblock-cipher is an algorithm that uses a block
# cipher repeatedly to securely transform amounts of data larger than a block.
abstract MultiBlockCipher

# @description Encrypts the given plaintext with the key set at initialization.
#
# @param {MultiBlockCipher} self      The cipher data struture.
# @param {AbstractString}   plaintext The message to encrypt.
#
# @return {Vector{UInt8}} The resulting ciphertext.
function encrypt(self::MultiBlockCipher, plaintext::AbstractString)
  return encrypt(self, convert(Array{UInt8}, plaintext))
end

# @description Encrypts the given plaintext with the key set at initialization.
#
# @param {MultiBlockCipher} self      The cipher data struture.
# @param {Vector{UInt8}}    plaintext The message to encrypt.
#
# @return {Vector{UInt8}} The resulting ciphertext.
function encrypt(self::MultiBlockCipher, plaintext::Vector{UInt8})
  return process(self, encrypt_next_blocks!, encrypt_last_block!, plaintext)
end

# @description Decrypts the given ciphertext with the key set at initialization.
#
# @param {MultiBlockCipher} sself       The cipher data struture.
# @param {Vector{UInt8}}    ciphertext The message to decrypt.
#
# @return {Vector{UInt8}} The resulting plaintext.
function decrypt(self::MultiBlockCipher, ciphertext::Vector{UInt8})
  return process(self, decrypt_next_blocks!, decrypt_last_block!, ciphertext)
end

# @description Encrypts or decrypts the given data with the key set at initialization.
#
# @param {MultiBlockCipher} self               The cipher data struture.
# @param {Function}         process_blocks     The cipher operation function.
# @param {Function}         process_last_block The cipher operation function.
# @param {Vector{UInt8}}    data               The message to process.
#
# @return {Vector{UInt8}} The processed data.
function process(self::MultiBlockCipher, process_blocks::Function, process_last_block::Function, data::Vector{UInt8})
  context     = deepcopy(self)
  bz          = block_size(context)
  blocks      = floor(UInt64, length(data) / bz)
  split_index = 1 + maximum(Int64[ 0, (blocks - 1) * bz])
  result      = UInt8[]

  reset!(context)

  if split_index > 1
    result = process_blocks(context, data[1:split_index-1])
  end

  return vcat(result, process_last_block(context, data[split_index:end]))
end
