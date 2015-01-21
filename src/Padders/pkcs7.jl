export Pkcs7
export pad, unpad

#' @@description Defines PKCS#7 the padding algorithm data struture.
immutable Pkcs7 <: PaddingAlgorithm
end

#' @@description Computes the padded block for the given plaintext chunk.
#'
#' @@param {Pkcs7}         self       The padding algorithm.
#' @@param {Vector{Uint8}} chunk      The plaintext chunk to pad. This must be shorter than the block size.
#' @@param {Integer}       block_size The cipher block size.
#'
#' @@return {Vector{UInt8}} The padded block.
function pad(self::Pkcs7, chunk::Vector{Uint8}, block_size::Integer)
end

#' @@description Removes the pad bytes from the given plaintext block.
#'
#' @@param {Pkcs7}         self  The padding algorithm.
#' @@param {Vector{Uint8}} block The padded block.
#'
#' @@return {Vector{UInt8}} The block without pad.
function unpad(self::Pkcs7, block::Vector{Uint8})
end
