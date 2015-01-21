export HashAlgorithm
export digest, hexdigest, updater

#'
#' @@name HashAlgorithm
#'
#' @@description Defines the hash algorithms abstract type.
#'
abstract HashAlgorithm

#' @@description Continue hashing of a message by consuming the next chunk of data.
#'
#' @@param  {HashAlgorithm}  self The hash algorithm.
#' @@param  {AbstractString} text The next message chunk.
#'
#' @@return The reference to the updated hash algorithm.
function update!(self::HashAlgorithm, text::AbstractString)
  update!(self, convert(Array{UInt8}, text))
end

#' @@description Computes the message digest of the given data.
#'
#' @@param {HashAlgorithm}  self The hash algorithm.
#' @@param {AbstractString} text The input message.
#'
#' @@return {Vector{Uint8}} The message digest.
function digest(self::HashAlgorithm, text::AbstractString)
  return digest(self, convert(Array{UInt8}, text))
end

#' @@description Computes the message digest of the given data.
#'
#' @@param {HashAlgorithm} self The hash algorithm.
#' @@param {Vector{Uint8}} data The input message.
#'
#' @@return {Vector{Uint8}} The message digest.
function digest(self::HashAlgorithm, data::Vector{Uint8})
  algorithm = deepcopy(self)

  reset!(algorithm)
  update!(algorithm, data)

  return digest(algorithm)
end

#' @@description Gets the digest of the data passed to the update!() method so far.
#'
#' @@param {HashAlgorithm} self The hash algorithm.
#'
#' @@return {Vector{Uint8}} The message digest as a string of double length, containing only hexadecimal digits.
function hexdigest(self::HashAlgorithm)
  return join([hex(x, 2) for x in digest(self)])
end

#' @@description Computes the message digest of the given data.
#'
#' @@param {HashAlgorithm} self The hash algorithm.
#' @@param {Vector{Uint8}} data The input message.
#'
#' @@return {Vector{Uint8}} The message digest as a string of double length, containing only hexadecimal digits.
function hexdigest(self::HashAlgorithm, data::Vector{Uint8})
  return join([hex(x, 2) for x in digest(self, data)])
end

#' @@description Computes the message digest of the given data.
#'
#' @@param {HashAlgorithm}  self The hash algorithm.
#' @@param {AbstractString} text The input message.
#'
#' @@return {Vector{Uint8}} The message digest as a string of double length, containing only hexadecimal digits.
function hexdigest(self::HashAlgorithm, data::AbstractString)
  return join([hex(x, 2) for x in digest(self, data)])
end

#' @@description Returns a update function linked to the given hash algorithm data structure.
#'
#' @@param {HashAlgorithm} self The hash algorithm.
#'
#' @@return {Function} A function that only takes one {Vector{Uint8}} argument.
function updater(self::HashAlgorithm)
  return data -> update!(self, data)
end
