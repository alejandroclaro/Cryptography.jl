#
# @description Defines the stream-cipher abstract type and the helper methods that act on this abstract type.
#
# @author Alejandro Claro (alejandro.claro@gmail.com)
#
# Copyright 2015 All rights reserved.
# Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.
#
export StreamCipher

# @description Defines the stream-cipher abstract type. A stream-cipher is a symmetric key cipher where plaintext
# digits are combined with a pseudorandom cipher digit stream.
abstract StreamCipher

# @description Returns the encryption function linked to the given stream-cipher.
#
# @param {StreamCipher} self The cipher data struture.
#
# @return {Function} A function that only takes one {Vector{UInt8}} argument.
function encryptor(self::StreamCipher)
  return plaintext -> encrypt(self, plaintext)
end

# @description Returns the decryption function linked to the given stream-cipher.
#
# @param {StreamCipher} self The cipher data struture.
#
# @return {Function} A function that only takes one {Vector{UInt8}} argument.
function decryptor(self::StreamCipher)
  return ciphertext -> decrypt(self, ciphertext)
end
