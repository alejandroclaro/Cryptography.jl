#
# @description Defines the Cryptography.Ciphers module.
#
# @author Alejandro Claro (alejandro.claro@gmail.com)
#
# Copyright 2015 All rights reserved.
# Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.
#

# @description Defines cipher block size error exception type.
type BlockSizeError <: Exception
end

# Abstract types.
include("Ciphers/stream_cipher.jl")
include("Ciphers/block_cipher.jl")
include("Ciphers/multiblock_cipher.jl")

# Stream ciphers.

# Block ciphers.
include("Ciphers/null_block_cipher.jl")
include("Ciphers/des_cipher.jl")

# Multi-block ciphers.
include("Ciphers/cbc_mode_cipher.jl")
