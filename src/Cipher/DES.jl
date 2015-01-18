#' @@description Defines the DES cipher data struture.
immutable DES <: BlockCipher
end

#' @@description Gets the cipher block size.
#'
#' @@param {DES} self The cipher data struture.
#'
#' @@return {Integer} The block size in bytes.
function block_size(cipher::DES)
  return 8
end

#' @@description Gets the cipher key size.
#'
#' @@param {DES} self The cipher data struture.
#'
#' @@return {Integer} The key size in bytes.
function key_size(cipher::DES)
  return 7
end

#' @@description Encrypts the given plaintext with the key set at initialization.
#'
#' @@param {DES}     self      The cipher data struture.
#' @@param {Message} plaintext The message to encrypt.
#'
#' @@return {Vector{Uint8}} The resulting ciphertext.
function encrypt(cipher::DES, plaintext::Message)
end

#' @@description Returns the encryption function linked to the given DES data structure.
#'
#' @@param {DES} self The cipher data struture.
#'
#' @@return {Function} A function that only takes one {Message} argument.
function encrypt(cipher::DES)
  return plaintext -> encrypt(algorithm, plaintext)
end

#' @@description Decrypts the given ciphertext with the key set at initialization.
#'
#' @@param {DES}     self       The cipher data struture.
#' @@param {Message} ciphertext The message to decrypt.
#'
#' @@return {Vector{Uint8}} The resulting plaintext.
function decrypt(cipher::DES, ciphertext::Message)
end

#' @@description Returns the decryption function linked to the given DES data structure.
#'
#' @@param {DES} self The cipher data struture.
#'
#' @@return {Function} A function that only takes one {Message} argument.
function decrypt(cipher::DES)
  return ciphertext -> decrypt(algorithm, ciphertext)
end
