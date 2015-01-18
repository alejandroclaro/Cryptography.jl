module Cipher

# Export abtract types.
export StreamCipher, BlockCipher, MultiBlockCipher

# Export block-ciphers.
export DES

# Export multiblock-ciphers.
export CBC

#' @@description Defines the stream-cipher abstract type. A stream-cipher is a symmetric key cipher where plaintext
#' digits are combined with a pseudorandom cipher digit stream.
abstract StreamCipher

#' @@description Defines the block-cipher abstract type. A block-cipher is a deterministic algorithm operating
#' on fixed-length groups of bits, called blocks, with an unvarying transformation that is specified by a
#' symmetric key.
abstract BlockCipher

#' @@description Defines the multiblock-cipher abstract type. A multiblock-cipher is an algorithm that uses a block
#' cipher repeatedly to securely transform amounts of data larger than a block.
abstract MultiBlockCipher

include("Cipher/DES.jl")
include("Cipher/CBC.jl")

end
