using ..Padding

#' @@description Defines the CBC cipher mode data struture.
immutable CBC <: MultiBlockCipher
  BlockCipher      blockcipher
  Vector{Uint8}    iv
  PaddingAlgorithm padding
end

#' @@description Gets the cipher block size.
#'
#' @@param {CBC} self The cipher data struture.
#'
#' @@return {Integer} The block size in bytes.
function block_size(cipher::CBC)
  return block_size(cipher.blockcipher)
end

#' @@description Gets the cipher key size.
#'
#' @@param {CBC} self The cipher data struture.
#'
#' @@return {Integer} The key size in bytes.
function key_size(cipher::CBC)
  return key_size(cipher.blockcipher)
end

#' @@description Gets the cipher initialization vector size.
#'
#' @@param {CBC} self The cipher data struture.
#'
#' @@return {Integer} The initialization vector size in bytes.
function iv_size(cipher::CBC)
  return block_size(cipher.blockcipher)
end

#' @@description Encrypts the given plaintext with the key set at initialization.
#'
#' @@param {CBC}     self      The cipher data struture.
#' @@param {Message} plaintext The message to encrypt.
#'
#' @@return {Vector{Uint8}} The resulting ciphertext.
function encrypt(cipher::CBC, plaintext::Message)
end

#' @@description Returns the encryption function linked to the given CBC data structure.
#'
#' @@param {CBC} self The cipher data struture.
#'
#' @@return {Function} A function that only takes one {Message} argument.
function encrypt(cipher::CBC)
  return plaintext -> encrypt(algorithm, plaintext)
end

#' @@description Decrypts the given ciphertext with the key set at initialization.
#'
#' @@param {CBC}     self       The cipher data struture.
#' @@param {Message} ciphertext The message to decrypt.
#'
#' @@return {Vector{Uint8}} The resulting plaintext.
function decrypt(cipher::CBC, ciphertext::Message)
end

#' @@description Returns the decryption function linked to the given CBC data structure.
#'
#' @@param {CBC} self The cipher data struture.
#'
#' @@return {Function} A function that only takes one {Message} argument.
function decrypt(cipher::CBC)
  return ciphertext -> decrypt(algorithm, ciphertext)
end

#' @@description Encrypts the given plaintext block.
#'
#' @@param {CBC}     self  The cipher data struture.
#' @@param {Message} block The block from the message to encrypt.
#'
#' @@return {Vector{Uint8}} The resulting ciphertext block.
function encrypt_block(cipher::CBC, block::Message)
end

#' @@description Encrypts the given last plaintext block.
#'
#' @@param {CBC}     self  The cipher data struture.
#' @@param {Message} block The last block from the message to encrypt.
#'
#' @@return {Vector{Uint8}} The resulting last ciphertext blocks. This could be more than the size of a block.
function encrypt_last_block(cipher::CBC, block::Message)
end

#' @@description Decrypts the given ciphertext block.
#'
#' @@param {CBC}     self  The cipher data struture.
#' @@param {Message} block The block from the message to decrypt.
#'
#' @@return {Vector{Uint8}} The resulting plaintext block.
function decrypt_block(cipher::CBC, block::Message)
end

#' @@description Decrypts the given last ciphertext block.
#'
#' @@param {CBC}     self  The cipher data struture.
#' @@param {Message} block The last block from the message to decrypt.
#'
#' @@return {Vector{Uint8}} The resulting last plaintext block. This could be less than the size of a block.
function decrypt_last_block(cipher::CBC, block::Message)
end
