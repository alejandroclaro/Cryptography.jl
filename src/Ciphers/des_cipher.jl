#
# @description Implements the DES (Data Encryption Standard) block cipher algorithms.
#
# @author Alejandro Claro (alejandro.claro@gmail.com)
#
# Copyright 2015 All rights reserved.
# Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.
#
export DesCipher
export DES_BLOCK_SIZE, DES_LEGAL_KEY_SIZES
export block_size, key_size, encrypt, decrypt

# @description Defines the DES cipher data struture.
immutable DesCipher <: BlockCipher
  subkeys::Vector{Vector{UInt8}}

  # @description Initialize the DES cipher.
  #
  # @param {Vector{UInt8}} key The symmetric key.
  function DesCipher(key::Vector{UInt8})
    return new(compute_des_subkeys(key))
  end
end

# @description The DES cipher block size in bytes.
const DES_BLOCK_SIZE = UInt64(8)

# @description The DES cipher legal key sizes in bytes.
const DES_LEGAL_KEY_SIZES = UInt64[ 8 ]

# @description Gets the cipher block size.
#
# @param {DesCipher} self The cipher data struture.
#
# @return {Integer} The block size in bytes.
function block_size(self::DesCipher)
  return DES_BLOCK_SIZE
end

# @description Gets the cipher key size.
#
# @param {DesCipher} self The cipher data struture.
#
# @return {Integer} The key size in bytes.
function key_size(self::DesCipher)
  return DES_LEGAL_KEY_SIZES[1]
end

# @description Encrypts the given plaintext block with the key set at initialization.
#
# @param {DesCipher}     self      The cipher data struture.
# @param {Vector{UInt8}} plaintext The message to encrypt.
#
# @return {Vector{UInt8}} The resulting ciphertext block.
function encrypt(self::DesCipher, plaintext::Vector{UInt8})
  if length(plaintext) != block_size(self)
    throw(ArgumentError("Invalid input plaintext length."))
  end

  feistel    = FeistelCipher(compute_des_round, self.subkeys, key_size(self), block_size(self))
  block      = permutate_bits(plaintext, DES_INITIAL_PERMUTATION)
  block      = encrypt(feistel, block)
  ciphertext = permutate_bits(block, DES_FINAL_PERMUTATION)

  return ciphertext
end

# @description Decrypts the given ciphertext block with the key set at initialization.
#
# @param {DesCipher}     self       The cipher data struture.
# @param {Vector{UInt8}} ciphertext The message to decrypt.
#
# @return {Vector{UInt8}} The resulting plaintext block.
function decrypt(self::DesCipher, ciphertext::Vector{UInt8})
  if length(ciphertext) != block_size(self)
    throw(ArgumentError("Invalid input ciphertext length."))
  end

  feistel   = FeistelCipher(compute_des_round, self.subkeys, key_size(self), block_size(self))
  block     = permutate_bits(ciphertext, DES_INITIAL_PERMUTATION)
  block     = decrypt(feistel, block)
  plaintext = permutate_bits(block, DES_FINAL_PERMUTATION)

  return plaintext
end

# PRIVATE IMPLEMENTATION #######################################################

# @description First permuted choice, used in the key schedule to select 56 bits from a 64-bit input.
const DES_PC1 = UInt8[
  57,   49,    41,   33,    25,    17,    9,
   1,   58,    50,   42,    34,    26,   18,
  10,    2,    59,   51,    43,    35,   27,
  19,   11,     3,   60,    52,    44,   36,
  63,   55,    47,   39,    31,    23,   15,
   7,   62,    54,   46,    38,    30,   22,
  14,    6,    61,   53,    45,    37,   29,
  21,   13,     5,   28,    20,    12,    4
]

# @description Schedule of "left shifts" for subkeys construction.
const DES_LEFT_SHIFTS = [ 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 ]

# @description Second permuted choice, used in the key schedule to produce each subkey.
const DES_PC2 = UInt8[
  14,    17,   11,    24,     1,    5,
   3,    28,   15,     6,    21,   10,
  23,    19,   12,     4,    26,    8,
  16,     7,   27,    20,    13,    2,
  41,    52,   31,    37,    47,   55,
  30,    40,   51,    45,    33,   48,
  44,    49,   39,    56,    34,   53,
  46,    42,   50,    36,    29,   32
]

# @description Initial permutation for the 64-bit input block.
const DES_INITIAL_PERMUTATION = UInt8[
  58,    50,   42,    34,    26,   18,    10,    2,
  60,    52,   44,    36,    28,   20,    12,    4,
  62,    54,   46,    38,    30,   22,    14,    6,
  64,    56,   48,    40,    32,   24,    16,    8,
  57,    49,   41,    33,    25,   17,     9,    1,
  59,    51,   43,    35,    27,   19,    11,    3,
  61,    53,   45,    37,    29,   21,    13,    5,
  63,    55,   47,    39,    31,   23,    15,    7
]

# @description Expansion of input block of 32 bits, producing an output block of 48 bits.
const DES_EXPANSION_FUNCTION = UInt8[
  32,     1,    2,     3,     4,    5,
   4,     5,    6,     7,     8,    9,
   8,     9,   10,    11,    12,   13,
  12,    13,   14,    15,    16,   17,
  16,    17,   18,    19,    20,   21,
  20,    21,   22,    23,    24,   25,
  24,    25,   26,    27,    28,   29,
  28,    29,   30,    31,    32,    1
]

# @description The DES' S-box 1
const DES_SBOX1 = UInt8[
  14   4  13   1   2  15  11   8   3  10   6  12   5   9   0   7;
   0  15   7   4  14   2  13   1  10   6  12  11   9   5   3   8;
   4   1  14   8  13   6   2  11  15  12   9   7   3  10   5   0;
  15  12   8   2   4   9   1   7   5  11   3  14  10   0   6  13
]

# @description The DES' S-box 2
const DES_SBOX2 = UInt8[
  15   1   8  14   6  11   3   4   9   7   2  13  12   0   5  10;
   3  13   4   7  15   2   8  14  12   0   1  10   6   9  11   5;
   0  14   7  11  10   4  13   1   5   8  12   6   9   3   2  15;
  13   8  10   1   3  15   4   2  11   6   7  12   0   5  14   9
]

# @description The DES' S-box 3
const DES_SBOX3 = UInt8[
  10   0   9  14   6   3  15   5   1  13  12   7  11   4   2   8;
  13   7   0   9   3   4   6  10   2   8   5  14  12  11  15   1;
  13   6   4   9   8  15   3   0  11   1   2  12   5  10  14   7;
   1  10  13   0   6   9   8   7   4  15  14   3  11   5   2  12
]

# @description The DES' S-box 4
const DES_SBOX4 = UInt8[
   7  13  14   3   0   6   9  10   1   2   8   5  11  12   4  15;
  13   8  11   5   6  15   0   3   4   7   2  12   1  10  14   9;
  10   6   9   0  12  11   7  13  15   1   3  14   5   2   8   4;
   3  15   0   6  10   1  13   8   9   4   5  11  12   7   2  14
]

# @description The DES' S-box 5
const DES_SBOX5 = UInt8[
   2  12   4   1   7  10  11   6   8   5   3  15  13   0  14   9;
  14  11   2  12   4   7  13   1   5   0  15  10   3   9   8   6;
   4   2   1  11  10  13   7   8  15   9  12   5   6   3   0  14;
  11   8  12   7   1  14   2  13   6  15   0   9  10   4   5   3
]

# @description The DES' S-box 6
const DES_SBOX6 = UInt8[
  12   1  10  15   9   2   6   8   0  13   3   4  14   7   5  11;
  10  15   4   2   7  12   9   5   6   1  13  14   0  11   3   8;
   9  14  15   5   2   8  12   3   7   0   4  10   1  13  11   6;
   4   3   2  12   9   5  15  10  11  14   1   7   6   0   8  13
]

# @description The DES' S-box 7
const DES_SBOX7 = UInt8[
   4  11   2  14  15   0   8  13   3  12   9   7   5  10   6   1;
  13   0  11   7   4   9   1  10  14   3   5  12   2  15   8   6;
   1   4  11  13  12   3   7  14  10  15   6   8   0   5   9   2;
   6  11  13   8   1   4  10   7   9   5   0  15  14   2   3  12
]

# @description The DES' S-box 8
const DES_SBOX8 = UInt8[
  13   2   8   4   6  15  11   1  10   9   3  14   5   0  12   7;
   1  15  13   8  10   3   7   4  12   5   6  11   0  14   9   2;
   7  11   4   1   9  12  14   2   0   6  10  13  15   3   5   8;
   2   1  14   7   4  10   8  13  15  12   9   0   3   5   6  11
]

# @description Collection of DES' S-boxes.
const DES_SBOXES = [ DES_SBOX1, DES_SBOX2, DES_SBOX3, DES_SBOX4, DES_SBOX5, DES_SBOX6, DES_SBOX7, DES_SBOX8 ]

# @description Predefined permutation for S-boxes output.
const DES_SBOX_PERMUTATION = UInt8[
  16,     7,    20,    21,
  29,    12,    28,    17,
   1,    15,    23,    26,
   5,    18,    31,    10,
   2,     8,    24,    14,
  32,    27,     3,     9,
  19,    13,    30,     6,
  22,    11,     4,    25
]

# @description Final permutation for the 4-bit preoutput block.
const DES_FINAL_PERMUTATION = UInt8[
  40,     8,   48,    16,    56,   24,    64,   32,
  39,     7,   47,    15,    55,   23,    63,   31,
  38,     6,   46,    14,    54,   22,    62,   30,
  37,     5,   45,    13,    53,   21,    61,   29,
  36,     4,   44,    12,    52,   20,    60,   28,
  35,     3,   43,    11,    51,   19,    59,   27,
  34,     2,   42,    10,    50,   18,    58,   26,
  33,     1,   41,     9,    49,   17,    57,   25
]

# @description Computes the subkey for DES algorithm.
#
# @param key The symmetric key.
#
# @return {Vector{Vector{UInt8}}} The set of subkeys (16 subkeys).
function compute_des_subkeys(key::Vector{UInt8})
  if length(key) ∉ DES_LEGAL_KEY_SIZES
    throw(ArgumentError("Invalid key length. $(length(key) * 8) bits provided, but 64 bits expected."))
  end

  result = Vector{Vector{UInt8}}()
  key    = permutate(unpack_bits(key), DES_PC1)
  cn     = key[1 : 28]
  dn     = key[29 : end]

  for i in 1 : 16
    for j in 1:DES_LEFT_SHIFTS[i]
      cn = circshift(cn, -1)
      dn = circshift(dn, -1)
    end

    subkey = permutate(vcat(cn, dn), DES_PC2)
    push!(result, subkey)
  end

  return result
end

# @description Computes the DES' f(*) function for the given R and subkey.
#
# @param {Vector{UInt8}} r   The R (right) bytes.
# @param {Vector{UInt8}} key The subkey for the DES iteration.
#
# @return {Vector{UInt8}} The round function value.
function compute_des_round(r::Vector{UInt8}, key::Vector{UInt8})
  r = permutate(r, DES_EXPANSION_FUNCTION)
  r = map($, r, key)

  b = [ r[1 : 6], r[7 : 12], r[13 : 18], r[19 : 24], r[25 : 30], r[31 : 36], r[37 : 42], r[43 : end] ]

  result = zeros(UInt8, 32)
  index  = 0

  for j in 1 : length(DES_SBOXES)
    m, n  = compute_permutation_position(b[j])
    value = DES_SBOXES[j][m + 1, n + 1]

    result[index + 1] = (value & 8) >> 3
    result[index + 2] = (value & 4) >> 2
    result[index + 3] = (value & 2) >> 1
    result[index + 4] = (value & 1) >> 0
    index += 4
  end

  return permutate(result, DES_SBOX_PERMUTATION)
end

# @description Computes the permutation position in the s-box(n).
#
# @param Vector{UInt8} bn The s-box indices.
#
# @return {Integer, Intenger} The permutation position.
function compute_permutation_position(bn::Vector{UInt8})
  m = (bn[1] << 1) + bn[6]
  n = (bn[2] << 3) + (bn[3] << 2) + (bn[4] << 1) + bn[5]

  return m, n
end
