#
# @@description Defines the Cryptography.Padders module.
#
# @@author Alejandro Claro (alejandro.claro@gmail.com)
#
# Copyright 2015 All rights reserved.
# Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.
#
module Padders

export PaddingAlgorithm

#' @@description Defines the multiblock-ciphers padding algorithm abstract type.
abstract PaddingAlgorithm

include("Padders/pkcs7.jl")

end
