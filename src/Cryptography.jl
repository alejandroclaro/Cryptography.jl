module Cryptography

#' @@description Defines the Cryptography Message as the union of AbstractString and Vector{Uint8} types.
typealias Message Union(AbstractString, Vector{Uint8})

include("Hash.jl")
include("Padding.jl")
include("Cipher.jl")

end
