module Padding

export PaddingAlgorithm
export Pkcs7

#' @@description Defines the multiblock-ciphers padding algorithm abstract type.
abstract PaddingAlgorithm

include("Padding/Pkcs7.jl")

end
