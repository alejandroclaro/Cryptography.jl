#
# @description Implements the MD5 hash algorithm as defined in RFC 1321.
#
# @author Alejandro Claro (alejandro.claro@gmail.com)
#
# Copyright 2015 All rights reserved.
# Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.
#
export Md5Hasher
export MD5_DIGEST_SIZE, MD5_BLOCK_SIZE
export digest_size, reset!, update!, digest

# @description Defines the MD5 algorithm data struture.
mutable struct Md5Hasher <: HashFunction
  scratch::Vector{UInt32}
  partial_block::Vector{UInt8}
  block_size::UInt32
  data_length::UInt64

  Md5Hasher() = reset!(new())
end

# @description The MD5 resulting message digest size in bytes.
const MD5_DIGEST_SIZE = 16

# @description The MD5 operation block size in bytes.
const MD5_BLOCK_SIZE = 64

# @description Gets the size of the resulting message digest in bytes.
#
# @param {Md5Hasher} self The hash algorithm.
#
# @return {Integer} The size of the resulting message digest in bytes.
function digest_size(self::Md5Hasher)
  return MD5_DIGEST_SIZE
end

# @description Resets the state of the MD5 data structure.
#
# @param {Md5Hasher} self The hash algorithm.
#
# @return The reference to the resetted hash algorithm.
function reset!(self::Md5Hasher)
  self.scratch       = UInt32[ 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476 ]
  self.partial_block = zeros(UInt8, MD5_BLOCK_SIZE)
  self.block_size    = 0
  self.data_length   = 0

  return self
end

# @description Continue hashing of a message by consuming the next chunk of data.
#
# @param  {Md5Hasher}     self The hash algorithm.
# @param  {Vector{UInt8}} data The next message chunk.
#
# @return The reference to the updated hash algorithm.
function update!(self::Md5Hasher, data::Vector{UInt8})
  index            = 0
  data_length      = length(data)
  self.data_length = self.data_length + data_length

  if self.block_size > 0
    data = vcat(self.partial_block[1 : self.block_size], data)
    self.block_size = 0
    data_length     = length(data)
  end

  while data_length >= (index + MD5_BLOCK_SIZE)
    process_block(self, data[(index + 1):(index + MD5_BLOCK_SIZE)])
    index += MD5_BLOCK_SIZE
  end

  if data_length > index
    setindex!(self.partial_block, data[(index + 1) : end], 1 : (data_length - index))
    self.block_size = data_length - index
  end

  return self
end

# @description Gets the digest of the data passed to the update!() method so far.
#
# @param {Md5Hasher} self The hash algorithm.
#
# @return {Vector{UInt8}} The message digest.
function digest(self::Md5Hasher)
  algorithm   = deepcopy(self)
  r           = algorithm.data_length % MD5_BLOCK_SIZE
  extra       = (r > 56) ? MD5_BLOCK_SIZE : 0
  last_block  = zeros(UInt8, extra + MD5_BLOCK_SIZE - r)
  len::UInt64 = algorithm.data_length << 3

  last_block[1]       = 0x80
  last_block[end - 7] = convert(UInt8, len & 0xFF)

  for i in 1:7
    last_block[end - 7 + i] = convert(UInt8, (len >> (8 * i)) & 0xFF)
  end

  update!(algorithm, last_block)
  @assert (algorithm.block_size == 0) "Block should be empty."

  result = zeros(UInt8, MD5_DIGEST_SIZE)

  for i in 1:length(algorithm.scratch)
    value = bitstring(algorithm.scratch[i])
    result[4 * (i - 1) + 1] = parse(UInt8, value[(end -  7) : (end -  0)], base = 2)
    result[4 * (i - 1) + 2] = parse(UInt8, value[(end - 15) : (end -  8)], base = 2)
    result[4 * (i - 1) + 3] = parse(UInt8, value[(end - 23) : (end - 16)], base = 2)
    result[4 * (i - 1) + 4] = parse(UInt8, value[(end - 31) : (end - 24)], base = 2)
  end

  return result
end

# PRIVATE IMPLEMENTATION #######################################################

# @description MD5 block processing shift constants.
const MD5_SHIFTS = UInt32[
  7, 12, 17, 22, 7, 12, 17, 22,  7, 12, 17, 22, 7, 12, 17, 22,
  5,  9, 14, 20, 5,  9, 14, 20,  5,  9, 14, 20, 5,  9, 14, 20,
  4, 11, 16, 23, 4, 11, 16, 23,  4, 11, 16, 23, 4, 11, 16, 23,
  6, 10, 15, 21, 6, 10, 15, 21,  6, 10, 15, 21, 6, 10, 15, 21
]

# @description MD5 block processing bytes constants.
const MD5_CONSTANTS_TABLE = UInt32[
  0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
  0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
  0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
  0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
  0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
  0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
  0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
  0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
]

# @description Process a block.
#
# @param {Md5Hasher}     self  The hash algorithm.
# @param {Vector{UInt8}} block The block data buffer.
function process_block(self::Md5Hasher, block::Vector{UInt8})
  a0::UInt32 = a::UInt32 = self.scratch[1]
  b0::UInt32 = b::UInt32 = self.scratch[2]
  c0::UInt32 = c::UInt32 = self.scratch[3]
  d0::UInt32 = d::UInt32 = self.scratch[4]

  buffer = [ bytes_to_int(block[i], block[i + 1], block[i + 2], block[i + 3]) for i in 1 : 4 : 64 ]

  for j in 0:63
    f::UInt32 = 0
    position  = j
    round     = j >> 4

    if round == 0
      f = (b & c) | (~b & d)
    elseif round == 1
      f = (b & d) | (c & ~d)
      position = (position * 5 + 1) & 0x0F
    elseif round == 2
      f = b ⊻ c ⊻ d
      position = (position * 3 + 5) & 0x0F
    else
      f = c ⊻ (b | ~d)
      position = (position * 7) & 0x0F
    end

    sa  = MD5_SHIFTS[j + 1]
    a  += f + buffer[position + 1] + MD5_CONSTANTS_TABLE[j + 1]

    a, d, c, b = (d, c, b, (a << sa | a >> (32 - sa) + b))
  end

  self.scratch[1] = a0 + a
  self.scratch[2] = b0 + b
  self.scratch[3] = c0 + c
  self.scratch[4] = d0 + d
end

# @description Packs the bytes into a integer value.
#
# @param {UInt8} a, b, c, d The bytes.
#
# @return {UInt32} The integer.
function bytes_to_int(a, b, c, d)
  return convert(UInt32, a) | convert(UInt32, b) << 8 | convert(UInt32, c) << 16 | convert(UInt32, d) << 24
end
