#
# @description Defines the Cryptography.Padders module.
#
# @author Alejandro Claro (alejandro.claro@gmail.com)
#
# Copyright 2015 All rights reserved.
# Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.
#
export PaddingMethod, PaddingError

# @description Defines the padding method abstract type.
abstract PaddingMethod

# @description Defines general padding error exception type.
type PaddingError <: Exception
end

include("Padders/ansix923_padder.jl")
include("Padders/pkcs7_padder.jl")
