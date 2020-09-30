#
# @description Implements the RC4 stream cipher algorithm.
#
# @author Alejandro Claro (alejandro.claro@gmail.com)
#
# Copyright 2017 All rights reserved.
# Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.
#
export Rc4Cipher

export RC4_LEGAL_KEY_SIZES
export key_size, reset!, encrypt!, decrypt!

# @description Defines the RC4 cipher data struture.
mutable struct Rc4Cipher <: StreamCipher
  key::Vector{UInt8}
  s::Vector{UInt8}
  i::UInt16
  j::UInt16

  # @description Initialize the RC4 cipher.
  #
  # @param {Vector{UInt8}} key The symmetric key.
  function Rc4Cipher(key::Vector{UInt8})
    return new(key, compute_rc4_ksa(key), 0, 0)
  end
end

# @description The DES cipher legal key sizes in bytes.
const RC4_LEGAL_KEY_SIZES = UInt64[ x for x in 1 : 32 ]

# @description Gets the cipher key size.
#
# @param {Rc4Cipher} self The cipher data struture.
#
# @return {Integer} The key size in bytes.
function key_size(self::Rc4Cipher)
  return length(self.key)
end

# @description Resets the state of the RC4 data structure.
#
# @param {Rc4Cipher} self The hash algorithm.
#
# @return The reference to the resetted hash algorithm.
function reset!(self::Rc4Cipher)
  self.s = compute_rc4_ksa(self.key)
  self.i = 0
  self.j = 0
end

# @description Encrypts the given plaintext block with the key set at initialization.
#
# @param {Rc4Cipher}     self      The cipher data struture.
# @param {Vector{UInt8}} plaintext The message to encrypt.
#
# @return {Vector{UInt8}} The resulting ciphertext block.
function encrypt!(self::Rc4Cipher, plaintext::Vector{UInt8})
  return transform_rc4_bytes!(self, plaintext)
end

# @description Decrypts the given ciphertext block with the key set at initialization.
#
# @param {Rc4Cipher}     self       The cipher data struture.
# @param {Vector{UInt8}} ciphertext The message to decrypt.
#
# @return {Vector{UInt8}} The resulting plaintext block.
function decrypt!(self::Rc4Cipher, ciphertext::Vector{UInt8})
  return transform_rc4_bytes!(self, ciphertext)
end

# PRIVATE IMPLEMENTATION #######################################################

# @description Computes the RC4 key-scheduling algorithm (KSA).
#
# @param {Vector{UInt8}} key The symmetric key.
#
# @return {Vector{UInt8}} The keystream 'S'.
function compute_rc4_ksa(key::Vector{UInt8})
  if length(key) ∉ RC4_LEGAL_KEY_SIZES
    throw(ArgumentError("Invalid key length. $(length(key) * 8) bits provided."))
  end

  s = UInt8[ x for x in 0 : 255 ]
  j = 0

  for i in 0 : 255
    k = mod(i, length(key))
    j = mod(j + s[i + 1] + key[k + 1], 256)
    s[i + 1], s[j + 1] = s[j + 1], s[i + 1]
  end

  return s
end

# @description Computes the RC4 Pseudo-random generation algorithm (PRGA).
#
# @param {Rc4Cipher} self The cipher data struture.
#
# @return {UInt8} The random byte.
function compute_next_rc4_number!(self::Rc4Cipher)
  self.i = mod(self.i + 1, 256)
  self.j = mod(self.j + self.s[self.i + 1], 256)
  index  = mod(self.s[self.i + 1] + self.s[self.j + 1], 256)

  self.s[self.i + 1], self.s[self.j + 1] = self.s[self.j + 1], self.s[self.i + 1]

  return self.s[index + 1]
end

# @description Transforms a RC4 byte's stream.
#
# @param {Rc4Cipher}     self The cipher data struture.
# @param {Vector{UInt8}} data The message to transform.
#
# @return {Vector{UInt8}} The resulting plaintext block.
function transform_rc4_bytes!(self::Rc4Cipher, data::Vector{UInt8})
  result = UInt8[]

  for x in data
    push!(result, x ⊻ compute_next_rc4_number!(self))
  end

  return result
end
