#
# @description Imolements of conversion helper functions.
#
# @author Alejandro Claro (alejandro.claro@gmail.com)
#
# Copyright 2017 All rights reserved.
# Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.
#

# @description Unpacks a sequence of bytes into a array of bits.
#
# @param {Vector{UInt8}} data The sequence of bytes.
#
# @return {Vector{UInt8}} The array of bits.
function unpack_bits(data::Vector{UInt8})
	result = zeros(UInt8, length(data) * 8)
	index  = 1

	for x in data
		bit = 7

		while bit >= 0
      mask = (1 << bit)
      result[index] = (x & mask) != 0 ? 1 : 0
			index += 1
			bit -= 1
    end
  end

  return result
end

# @description Packs a sequence of bits into a array of bytes.
#
# @param {Vector{UInt8}} data The sequence of bits.
#
# @return {Vector{UInt8}} The array of bytes.
function pack_bits(data::Vector{UInt8})
  if length(data) % 8 != 0
    throw(ArgumentError("Could not pack bits. The bit array must be divisible by 8."))
  end

  result = zeros(UInt8, div(length(data) + 7, 8))

  for index in 1 : length(result)
    byte  = (index - 1) * 8
    value = 0

    for bit in  1 :8
      value += data[byte + bit] << (8 - bit)
    end

    result[index] = value
  end

  return result
end

# @description Permutates the given block using the specified table.
#
# @param {Vector{UInt8}} block The block to transform.
# @param {Vector{UInt8}} table The permutation table.
#
# @return {Vector{UInt8}} The permutation.
function permutate(block::Vector{UInt8}, table::Vector{UInt8})
  return [block[index] for index in table]
end
