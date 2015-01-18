module Hash

export HashAlgorithm
export MD5

#'
#' @@name HashAlgorithm
#'
#' @@description Defines the hash algorithms abstract type.
#'
abstract HashAlgorithm

include("Hash/MD5.jl")

end
