using Cryptography
using Base.Test

tests = [ "Hashers/md5" "Padders/pkcs7" ]

for t in tests
  include("$(t).jl")
end
