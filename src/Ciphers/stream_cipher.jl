export StreamCipher

#' @@description Defines the stream-cipher abstract type. A stream-cipher is a symmetric key cipher where plaintext
#' digits are combined with a pseudorandom cipher digit stream.
abstract StreamCipher

#' @@description Returns the encryption function linked to the given stream-cipher.
#'
#' @@param {StreamCipher} self The cipher data struture.
#'
#' @@return {Function} A function that only takes one {Vector{Uint8}} argument.
function encryptor(self::StreamCipher)
  return plaintext -> encrypt(self, plaintext)
end

#' @@description Returns the decryption function linked to the given stream-cipher.
#'
#' @@param {StreamCipher} self The cipher data struture.
#'
#' @@return {Function} A function that only takes one {Vector{Uint8}} argument.
function decryptor(self::StreamCipher)
  return ciphertext -> decrypt(self, ciphertext)
end
