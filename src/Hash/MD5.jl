#' @@description Defines the MD5 algorithm data struture.
type MD5 <: HashAlgorithm
end

#' @@description Gets the size of the resulting message digest in bytes.
#'
#' @@param {MD5} self The hash algorithm.
#'
#' @@return {Integer} The size of the resulting message digest in bytes.
function digest_size(self::MD5)
  return 16
end

#' @@description Continue hashing of a message by consuming the next chunk of data.
#'
#' @@param  {MD5}     self The hash algorithm.
#' @@param  {Message} text The next message chunk.
function update(self::MD5, text::Message)
end

#' @@description Returns a update function linked to the given MD5 data structure.
#'
#' @@param {MD5} self The hash algorithm.
#'
#' @@return {Function} A function that only takes one {Message} argument.
function update(self::MD5)
  return text -> update(algorithm, text)
end

#' @@description Completes the message digest.
#'
#' @@param {MD5} self The hash algorithm.
#'
#' @@return {Vector{Uint8}} The message digest.
function digest(self::MD5)
end
