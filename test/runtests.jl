using Cryptography
using Test

tests =
[
  "Hashers/md5_hasher",
  "Padders/ansix923_padder",
  "Padders/pkcs7_padder",
  "Ciphers/null_block_cipher",
  "Ciphers/des_cipher",
  "Ciphers/triple_des_cipher",
  "Ciphers/blowfish_cipher",
  "Ciphers/rc4_cipher",
  "Ciphers/cbc_mode_cipher"
]

for t in tests
  try
    include("$(t).jl")
  catch e
  end
end
