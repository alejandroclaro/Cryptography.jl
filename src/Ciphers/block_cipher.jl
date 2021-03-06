#
# @description Defines the block-cipher abstract type and the helper methods that act on this abstract type.
#
# @author Alejandro Claro (alejandro.claro@gmail.com)
#
# Copyright 2015 All rights reserved.
# Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.
#
export BlockCipher
export encryptor, decryptor

# @description Defines the block-cipher abstract type. A block-cipher is a deterministic algorithm operating
# on fixed-length groups of bits, called blocks, with an unvarying transformation that is specified by a
# symmetric key.
abstract type BlockCipher end

# @description Returns the encryption function linked to the given block-cipher.
#
# @param {BlockCipher} self The cipher data struture.
#
# @return {Function} A function that only takes one {Vector{UInt8}} argument.
function encryptor(self::BlockCipher)
  return plaintext -> encrypt(self, plaintext)
end

# @description Returns the decryption function linked to the given block-cipher.
#
# @param {BlockCipher} self The cipher data struture.
#
# @return {Function} A function that only takes one {Vector{UInt8}} argument.
function decryptor(self::BlockCipher)
  return ciphertext -> decrypt(self, ciphertext)
end
