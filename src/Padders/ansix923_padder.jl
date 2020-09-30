#
# @description Implementation of ANSIX923 padding functions.
#
# @author Alejandro Claro (alejandro.claro@gmail.com)
#
# Copyright 2015 All rights reserved.
# Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.
#
export Ansix923Padder
export pad, unpad

# @description Defines PKCS#7 the padding algorithm data struture.
struct Ansix923Padder <: PaddingMethod end

# @description Computes the padded block for the given plaintext chunk.
#
# @param {Ansix923Padder} self       The padding algorithm.
# @param {Vector{UInt8}}  chunk      The plaintext chunk to pad. This must be shorter than the block size.
# @param {Integer}        block_size The cipher block size.
#
# @return {Vector{UInt8}} The padded block.
function pad(self::Ansix923Padder, chunk::Vector{UInt8}, block_size::Integer)
  len = block_size - (length(chunk) % block_size)
  return vcat(chunk, zeros(UInt8, len - 1), len)
end

# @description Removes the pad bytes from the given plaintext block.
#
# @param {Ansix923Padder} self  The padding algorithm.
# @param {Vector{UInt8}}  block The padded block.
#
# @return {Vector{UInt8}} The block without pad.
function unpad(self::Ansix923Padder, block::Vector{UInt8})
  if block[end] == 0x00 || block[end] > length(block)
    throw(PaddingError())
  end

  if findfirst(x -> x != 0, block[(end - block[end] + 1) : (end - 1)]) != 0
    throw(PaddingError())
  end

  return block[1 : (end - block[end])]
end
