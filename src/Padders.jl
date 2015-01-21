module Padders

export PaddingAlgorithm

#' @@description Defines the multiblock-ciphers padding algorithm abstract type.
abstract PaddingAlgorithm

include("Padders/pkcs7.jl")

end
