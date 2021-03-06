#
# @description Defines the Cryptography.Ciphers module.
#
# @author Alejandro Claro (alejandro.claro@gmail.com)
#
# Copyright 2015 All rights reserved.
# Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.
#
export BlockSizeError

# @description Defines cipher block size error exception type.
struct BlockSizeError <: Exception end

# Helpers
include("Ciphers/conversion.jl")

# Abstract types.
include("Ciphers/stream_cipher.jl")
include("Ciphers/block_cipher.jl")
include("Ciphers/multiblock_cipher.jl")

# Block ciphers.
include("Ciphers/null_block_cipher.jl")
include("Ciphers/feistel_cipher.jl")
include("Ciphers/des_cipher.jl")
include("Ciphers/triple_des_cipher.jl")
include("Ciphers/blowfish_cipher.jl")
include("Ciphers/rc4_cipher.jl")

# Multi-block ciphers.
include("Ciphers/cbc_mode_cipher.jl")

# Stream ciphers.
