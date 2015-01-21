export BlockCipher
export encryptor, decryptor

#' @@description Defines the block-cipher abstract type. A block-cipher is a deterministic algorithm operating
#' on fixed-length groups of bits, called blocks, with an unvarying transformation that is specified by a
#' symmetric key.
abstract BlockCipher

#' @@description Returns the encryption function linked to the given block-cipher.
#'
#' @@param {BlockCipher} self The cipher data struture.
#'
#' @@return {Function} A function that only takes one {Vector{Uint8}} argument.
function encryptor(cipher::BlockCipher)
  return plaintext -> encrypt(cipher, plaintext)
end

#' @@description Returns the decryption function linked to the given block-cipher.
#'
#' @@param {BlockCipher} self The cipher data struture.
#'
#' @@return {Function} A function that only takes one {Vector{Uint8}} argument.
function decryptor(cipher::BlockCipher)
  return ciphertext -> decrypt(cipher, ciphertext)
end
