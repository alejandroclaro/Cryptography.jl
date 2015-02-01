#
# @@description Implements the DES (Data Encryption Standard) block cipher algorithms.
#
# @@author Alejandro Claro (alejandro.claro@gmail.com)
#
# Copyright 2015 All rights reserved.
# Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.
#
export DES
export DES_BLOCK_SIZE, DES_LEGAL_KEY_SIZES
export block_size, key_size, encrypt, decrypt

#' @@description Defines the DES cipher data struture.
immutable DES <: BlockCipher
  key::Vector{Uint8}

  function DES(key::Vector{Uint8})
    if length(key) != 7
      error("Invalid key length.")
    end

    return new(key)
  end
end

#' @@description The DES cipher block size in bytes.
const DES_BLOCK_SIZE = 8

#' @@description The DES cipher legal key sizes in bytes.
const DES_LEGAL_KEY_SIZES = [ 7 ]

#' @@description Gets the cipher block size.
#'
#' @@param {DES} self The cipher data struture.
#'
#' @@return {Integer} The block size in bytes.
function block_size(self::DES)
  return DES_BLOCK_SIZE
end

#' @@description Gets the cipher key size.
#'
#' @@param {DES} self The cipher data struture.
#'
#' @@return {Integer} The key size in bytes.
function key_size(self::DES)
  return length(key)
end

#' @@description Encrypts the given plaintext with the key set at initialization.
#'
#' @@param {DES}           self      The cipher data struture.
#' @@param {Vector{Uint8}} plaintext The message to encrypt.
#'
#' @@return {Vector{Uint8}} The resulting ciphertext.
function encrypt(self::DES, plaintext::Vector{Uint8})
end

#' @@description Decrypts the given ciphertext with the key set at initialization.
#'
#' @@param {DES}           self       The cipher data struture.
#' @@param {Vector{Uint8}} ciphertext The message to decrypt.
#'
#' @@return {Vector{Uint8}} The resulting plaintext.
function decrypt(self::DES, ciphertext::Vector{Uint8})
end
