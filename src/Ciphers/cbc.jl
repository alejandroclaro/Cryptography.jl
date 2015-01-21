using ..Padders

export CBC
export block_size, key_size, iv_size, iv, encrypt_block, encrypt_last_block, decrypt_block, decrypt_last_block

#' @@description Defines the CBC cipher mode data struture.
type CBC <: MultiBlockCipher
  blockcipher::BlockCipher
  padder::PaddingAlgorithm
  iv::Vector{Uint8}

  #' @@description Initialize the CBC cipher with a random initialization vector.
  #'
  #' @@param {BlockCipher}      blockcipher The block cipher.
  #' @@param {PaddingAlgorithm} padder      The padding algorithm.
  function CBC(blockcipher::BlockCipher, padder::PaddingAlgorithm)
    # TODO: Generate random IV using cryptographic secure RNG.
    return new(blockcipher, padder, rand(Uint8, block_size(blockcipher)))
  end

  #' @@description Initialize the CBC cipher.
  #'
  #' @@param {BlockCipher}      blockcipher The block cipher.
  #' @@param {PaddingAlgorithm} padder      The padding algorithm.
  #' @@param {Vector{Uint8}}    iv          The initialization vector.
  function CBC(blockcipher::BlockCipher, padder::PaddingAlgorithm, iv::Vector{Uint8})
    if length(iv) != block_size(blockcipher)
      error("Invalid initialization vector length.")
    end

    return new(blockcipher, padder, iv)
  end
end

#' @@description Gets the cipher block size.
#'
#' @@param {CBC} self The cipher data struture.
#'
#' @@return {Integer} The block size in bytes.
function block_size(self::CBC)
  return block_size(self.blockcipher)
end

#' @@description Gets the cipher key size.
#'
#' @@param {CBC} self The cipher data struture.
#'
#' @@return {Integer} The key size in bytes.
function key_size(self::CBC)
  return key_size(self.blockcipher)
end

#' @@description Gets the cipher initialization vector size.
#'
#' @@param {CBC} self The cipher data struture.
#'
#' @@return {Integer} The initialization vector size in bytes.
function iv_size(self::CBC)
  return block_size(self.blockcipher)
end

#' @@description Gets the cipher initialization vector.
#'
#' @@param {CBC} self The cipher data struture.
#'
#' @@return {Vector{UInt8}} The initialization vector.
function iv(self::CBC)
  return self.iv
end

#' @@description Encrypts the given plaintext block.
#'
#' @@param {CBC}           self  The cipher data struture.
#' @@param {Vector{Uint8}} block The block from the message to encrypt.
#'
#' @@return {Vector{Uint8}} The resulting ciphertext block.
function encrypt_block!(self::CBC, block::Vector{Uint8})
  # TODO:
end

#' @@description Encrypts the given last plaintext block.
#'
#' @@param {CBC}           self  The cipher data struture.
#' @@param {Vector{Uint8}} block The last block from the message to encrypt.
#'
#' @@return {Vector{Uint8}} The resulting last ciphertext blocks. This could be more than the size of a block.
function encrypt_last_block!(self::CBC, block::Vector{Uint8})
  # TODO:
end

#' @@description Decrypts the given ciphertext block.
#'
#' @@param {CBC}           self  The cipher data struture.
#' @@param {Vector{Uint8}} block The block from the message to decrypt.
#'
#' @@return {Vector{Uint8}} The resulting plaintext block.
function decrypt_block!(self::CBC, block::Vector{Uint8})
  # TODO:
end

#' @@description Decrypts the given last ciphertext block.
#'
#' @@param {CBC}           self  The cipher data struture.
#' @@param {Vector{Uint8}} block The last block from the message to decrypt.
#'
#' @@return {Vector{Uint8}} The resulting last plaintext block. This could be less than the size of a block.
function decrypt_last_block!(self::CBC, block::Vector{Uint8})
  # TODO:
end
