export MultiBlockCipher
export encryptor, decryptor, encrypt, decrypt

#' @@description Defines the multiblock-cipher abstract type. A multiblock-cipher is an algorithm that uses a block
#' cipher repeatedly to securely transform amounts of data larger than a block.
abstract MultiBlockCipher

#' @@description Returns the encryption function linked to the given multiblock-cipher.
#'
#' @@param {MultiBlockCipher} self The cipher data struture.
#'
#' @@return {Function} A function that only takes one {Vector{Uint8}} argument.
function encryptor(self::MultiBlockCipher)
  return plaintext -> encrypt(self, plaintext)
end

#' @@description Returns the decryption function linked to the given multiblock-cipher.
#'
#' @@param {MultiBlockCipher} self The cipher data struture.
#'
#' @@return {Function} A function that only takes one {Vector{Uint8}} argument.
function decryptor(self::MultiBlockCipher)
  return ciphertext -> decrypt(self, ciphertext)
end

#' @@description Encrypts the given plaintext with the key set at initialization.
#'
#' @@param {MultiBlockCipher} self      The cipher data struture.
#' @@param {Vector{Uint8}}    plaintext The message to encrypt.
#'
#' @@return {Vector{Uint8}} The resulting ciphertext.
function encrypt(self::MultiBlockCipher, plaintext::Vector{Uint8})
  # TODO:
end

#' @@description Decrypts the given ciphertext with the key set at initialization.
#'
#' @@param {MultiBlockCipher} sself       The cipher data struture.
#' @@param {Vector{Uint8}}    ciphertext The message to decrypt.
#'
#' @@return {Vector{Uint8}} The resulting plaintext.
function decrypt(self::MultiBlockCipher, ciphertext::Vector{Uint8})
  # TODO:
end
