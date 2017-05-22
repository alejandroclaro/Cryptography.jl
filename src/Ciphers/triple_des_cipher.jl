#
# @description Implements the 3DES (DES-EDE1, DES-EDE2, and DES-EDE3) block cipher algorithms.
#
# @author Alejandro Claro (alejandro.claro@gmail.com)
#
# Copyright 2017 All rights reserved.
# Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.
#
export TripleDesCipher
export TRIPLE_DES_BLOCK_SIZE, TRIPLE_DES_LEGAL_KEY_SIZES
export block_size, key_size, encrypt, decrypt

# @description Defines the 3DES cipher data struture.
immutable TripleDesCipher <: BlockCipher
  des::Array{DesCipher}
  key_size::UInt64

  # @description Initialize the 3DES cipher.
  #
  # @param {Vector{UInt8}} key The symmetric key.
  function TripleDesCipher(key::Vector{UInt8})
    des_keys = []

    if length(key) == TRIPLE_DES_LEGAL_KEY_SIZES[1]
      des_keys = [ key, key, key ]
    elseif length(key) == TRIPLE_DES_LEGAL_KEY_SIZES[2]
      des_keys = [ key[1 : 8], key[9 : 16], key[1 : 8] ]
    elseif length(key) == TRIPLE_DES_LEGAL_KEY_SIZES[3]
      des_keys = [ key[1 : 8], key[9 : 16], key[17 : 24] ]
    else
      throw(ArgumentError("Invalid key length. $(length(key) * 8) bits provided."))
    end

    return new([ DesCipher(des_keys[1]), DesCipher(des_keys[2]), DesCipher(des_keys[3]) ], length(key))
  end
end

# @description The 3DES cipher block size in bytes.
const TRIPLE_DES_BLOCK_SIZE = UInt64(8)

# @description The 3DES cipher legal key sizes in bytes.
const TRIPLE_DES_LEGAL_KEY_SIZES = UInt64[ 8, 16, 24 ]

# @description Gets the cipher block size.
#
# @param {TripleDesCipher} self The cipher data struture.
#
# @return {Integer} The block size in bytes.
function block_size(self::TripleDesCipher)
  return TRIPLE_DES_BLOCK_SIZE
end

# @description Gets the cipher key size.
#
# @param {TripleDesCipher} self The cipher data struture.
#
# @return {Integer} The key size in bytes.
function key_size(self::TripleDesCipher)
  return self.key_size
end

# @description Encrypts the given plaintext block with the key set at initialization.
#
# @param {TripleDesCipher} self      The cipher data struture.
# @param {Vector{UInt8}}   plaintext The message to encrypt.
#
# @return {Vector{UInt8}} The resulting ciphertext block.
function encrypt(self::TripleDesCipher, plaintext::Vector{UInt8})
  result = encrypt(self.des[1], plaintext)
  result = decrypt(self.des[2], result)
  result = encrypt(self.des[3], result)
  return result
end

# @description Decrypts the given ciphertext block with the key set at initialization.
#
# @param {TripleDesCipher} self       The cipher data struture.
# @param {Vector{UInt8}}   ciphertext The message to decrypt.
#
# @return {Vector{UInt8}} The resulting plaintext block.
function decrypt(self::TripleDesCipher, ciphertext::Vector{UInt8})
  result = decrypt(self.des[3], ciphertext)
  result = encrypt(self.des[2], result)
  result = decrypt(self.des[1], result)
  return result
end
