#
# @@description Implements the MD5 hash algorithm as defined in RFC 1321.
#
# @@author Alejandro Claro (alejandro.claro@gmail.com)
#
# Copyright 2015 All rights reserved.
# Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.
#
export MD5
export MD5_DIGEST_SIZE, MD5_BLOCK_SIZE
export digest_size, reset!, update!, digest

#' @@description Defines the MD5 algorithm data struture.
type MD5 <: HashAlgorithm
  scratch::Vector{UInt32}
  buffer::Vector{UInt8}
  buffer_position::UInt32
  data_length::UInt64

  #' @@description Constructs the MD5 data structure.
  function MD5()
    result = new()
    reset!(result)

    return result
  end
end

#' @@description The MD5 resulting message digest size in bytes.
const MD5_DIGEST_SIZE = 16

#' @@description The MD5 operation block size in bytes.
const MD5_BLOCK_SIZE = 64

#' @@description MD5 block processing shift constants.
const SHIFT = UInt32[
  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
]

#' @@description MD5 block processing bytes constants.
const CONSTANT_TABLE = UInt32[
  0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
  0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
  0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
  0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
  0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
  0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
  0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
  0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
]

#' @@description Gets the size of the resulting message digest in bytes.
#'
#' @@param {MD5} self The hash algorithm.
#'
#' @@return {Integer} The size of the resulting message digest in bytes.
function digest_size(self::MD5)
  return MD5_DIGEST_SIZE
end

#' @@description Resets the state of the MD5 data structure.
#'
#' @@param {MD5} self The hash algorithm.
#'
#' @@return The reference to the resetted hash algorithm.
function reset!(self::MD5)
  self.scratch         = UInt32[ 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476 ]
  self.buffer          = zeros(UInt8, MD5_BLOCK_SIZE)
  self.buffer_position = 0
  self.data_length     = 0

  return self
end

#' @@description Continue hashing of a message by consuming the next chunk of data.
#'
#' @@param  {MD5}           self The hash algorithm.
#' @@param  {Vector{Uint8}} data The next message chunk.
#'
#' @@return The reference to the updated hash algorithm.
function update!(self::MD5, data::Vector{Uint8})
  if self.buffer_position > 0
    chunck_length = min(length(data), MD5_BLOCK_SIZE - self.buffer_position)
    last          = self.buffer_position + chunck_length - 1

    setindex!(self.buffer, data[1:chunck_length], self.buffer_position:last)
    self.buffer_position += chunck_length

    if self.buffer_position == MD5_BLOCK_SIZE
      process_block(self, self.buffer)
      self.buffer_position = 0
    end

    println(chunck_length)
    data = data[chunck_length:end]
  end

  index       = 0
  data_length = length(data)

  while data_length >= (index + MD5_BLOCK_SIZE)
    process_block(self, data[(index + 1):(index + MD5_BLOCK_SIZE)])
    index += MD5_BLOCK_SIZE
  end

  if data_length > index
    setindex!(self.buffer, data[index:end], 1:(data_length - index + 1))
    self.buffer_position = data_length - index
    println(self.buffer_position)
  end

  self.data_length += data_length
  return self
end

#' @@description Gets the digest of the data passed to the update!() method so far.
#'
#' @@param {MD5} self The hash algorithm.
#'
#' @@return {Vector{Uint8}} The message digest.
function digest(self::MD5)
  algorithm = deepcopy(self)
  r         = algorithm.data_length % MD5_BLOCK_SIZE
  extra     = (r < 56) ? 0 : 64

  update!(algorithm, [ 0x80, zeros(UInt8, extra + 55 - r) ])

  len        = algorithm.data_length << 3
  final_data = UInt8[ convert(UInt8, len >> (8 * i)) for i in 1:8 ]

  update!(algorithm, final_data[1:8])
  assert(algorithm.buffer_position == 0)

  result = zeros(UInt8, MD5_DIGEST_SIZE)

  for i in 1:length(self.scratch)
    value = bits(self.scratch[i])
    result[4 * (i - 1) + 1] = parseint(UInt8, value[(end -  7):(end -  0)], 2)
    result[4 * (i - 1) + 2] = parseint(UInt8, value[(end - 15):(end -  8)], 2)
    result[4 * (i - 1) + 3] = parseint(UInt8, value[(end - 23):(end - 16)], 2)
    result[4 * (i - 1) + 4] = parseint(UInt8, value[(end - 31):(end - 24)], 2)
  end

  return result
end

#' @@description Process a block.
#'
#' @@param {MD5}           self  The hash algorithm.
#' @@param {Vector{UInt8}} block The block data buffer.
function process_block(self::MD5, block::Vector{UInt8})
  a0::UInt32 = a::UInt32 = self.scratch[1]
  b0::UInt32 = b::UInt32 = self.scratch[2]
  c0::UInt32 = c::UInt32 = self.scratch[3]
  d0::UInt32 = d::UInt32 = self.scratch[4]

  buffer = [ bytes_to_int(block[i], block[i + 1], block[i + 2], block[i + 3]) for i in 1:4:64 ]

  for j in 0:63
    f::UInt32       = 0
    buffer_position = j
    round           = j >> 4

    if round == 0
      f = (b & c) | (~b & d)
    elseif round == 1
      f = (b & d) | (c & ~d)
      buffer_position = (buffer_position * 5 + 1) & 0x0F
    elseif round == 2
      f = b $ c $ d
      buffer_position = (buffer_position * 3 + 5) & 0x0F
    else
      f = c $ (b | ~d)
      buffer_position = (buffer_position * 7) & 0x0F
    end

    sa  = SHIFT[j + 1]
    a  += f + buffer[buffer_position + 1] + CONSTANT_TABLE[j + 1]

    a, d, c, b = (d, c, b, (a << sa | a >> (32 - sa) +b))
  end

  self.scratch[1] = a0 + a
  self.scratch[2] = b0 + b
  self.scratch[3] = c0 + c
  self.scratch[4] = d0 + d
end

#' @@description Packs the bytes into a integer value.
#'
#' @@param {UInt8}         a, b, c, d  The bytes.
#'
#' @@return {UInt32} The integer.
function bytes_to_int(a, b, c, d)
  return convert(UInt32, a) | convert(UInt32, b) << 8 | convert(UInt32, c) << 16 | convert(UInt32, d) << 24
end
