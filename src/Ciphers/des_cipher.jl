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
  key::Vector{UInt8}

  function DesCipher(key::Vector{UInt8})
    if length(key) != 7
      throw(ArgumentError("Invalid key length. $(length(key) * 8) bits provided, but $(7 * 8) bits expected."))
    end

    return new(key)
  end
end

# @description The DES cipher block size in bytes.
const DES_BLOCK_SIZE = UInt64(8)

# @description The DES cipher legal key sizes in bytes.
const DES_LEGAL_KEY_SIZES = UInt64[ 7 ]

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
  return length(key)
end

# @description Encrypts the given plaintext block with the key set at initialization.
#
# @param {DesCipher}     self      The cipher data struture.
# @param {Vector{UInt8}} plaintext The message to encrypt.
#
# @return {Vector{UInt8}} The resulting ciphertext block.
function encrypt(self::DesCipher, plaintext::Vector{UInt8})
end

# @description Decrypts the given ciphertext block with the key set at initialization.
#
# @param {DesCipher}     self       The cipher data struture.
# @param {Vector{UInt8}} ciphertext The message to decrypt.
#
# @return {Vector{UInt8}} The resulting plaintext block.
function decrypt(self::DesCipher, ciphertext::Vector{UInt8})
end
