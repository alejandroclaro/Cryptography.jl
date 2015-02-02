using Cryptography
using Base.Test

tests =
[
  "Hashers/md5_hasher",
  "Padders/ansix923_padder",
  "Padders/pkcs7_padder",
  "Ciphers/null_block_cipher",
  "Ciphers/cbc_mode_cipher"
]

for t in tests
  include("$(t).jl")
end
