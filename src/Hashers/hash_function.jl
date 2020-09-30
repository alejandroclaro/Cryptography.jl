#
# @description Defines the hash-function abstract type and implements helper methods that act on this abstract type.
#
# @author Alejandro Claro (alejandro.claro@gmail.com)
#
# Copyright 2015 All rights reserved.
# Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.
#
export HashFunction
export digest, hexdigest, updater

# @description Defines the hash algorithms abstract type.
abstract type HashFunction end

# @description Continue hashing of a message by consuming the next chunk of data.
#
# @param  {HashFunction}   self The hash algorithm.
# @param  {AbstractString} text The next message chunk.
#
# @return The reference to the updated hash algorithm.
function update!(self::HashFunction, text::AbstractString)
  update!(self, Array{UInt8}(text))
end

# @description Computes the message digest of the given data.
#
# @param {HashFunction}   self The hash algorithm.
# @param {AbstractString} text The input message.
#
# @return {Vector{UInt8}} The message digest.
function digest(self::HashFunction, text::AbstractString)
  return digest(self, Array{UInt8}(text))
end

# @description Computes the message digest of the given data.
#
# @param {HashFunction}  self The hash algorithm.
# @param {Vector{UInt8}} data The input message.
#
# @return {Vector{UInt8}} The message digest.
function digest(self::HashFunction, data::Vector{UInt8})
  context = deepcopy(self)

  reset!(context)
  update!(context, data)

  return digest(context)
end

# @description Gets the digest of the data passed to the update!() method so far.
#
# @param {HashFunction} self The hash algorithm.
#
# @return {Vector{UInt8}} The message digest as a string of double length, containing only hexadecimal digits.
function hexdigest(self::HashFunction)
  return join([string(x, 16, 2) for x in digest(self)])
end

# @description Computes the message digest of the given data.
#
# @param {HashFunction} self The hash algorithm.
# @param {Vector{UInt8}} data The input message.
#
# @return {Vector{UInt8}} The message digest as a string of double length, containing only hexadecimal digits.
function hexdigest(self::HashFunction, data::Vector{UInt8})
  return join([string(x, 16, 2) for x in digest(self, data)])
end

# @description Computes the message digest of the given data.
#
# @param {HashFunction}  self The hash algorithm.
# @param {AbstractString} text The input message.
#
# @return {Vector{UInt8}} The message digest as a string of double length, containing only hexadecimal digits.
function hexdigest(self::HashFunction, data::AbstractString)
  return join([string(x, 16,  2) for x in digest(self, data)])
end

# @description Returns a update function linked to the given hash algorithm data structure.
#
# @param {HashFunction} self The hash algorithm.
#
# @return {Function} A function that only takes one {Vector{UInt8}} argument.
function updater(self::HashFunction)
  return data -> update!(self, data)
end
