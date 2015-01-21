using Cryptography
using Base.Test

tests = [ "padders/pkcs7" ]

for t in tests
  include("$(t).jl")
end
