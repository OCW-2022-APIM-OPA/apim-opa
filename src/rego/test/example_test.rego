admin_token := io.jwt.encode_sing({
  "typ": "JWT",
  "alg": "HS256"
}, {
  "roles": {
    "admin"
  }
}, {
  "kty": "oct",{
  "k": "test-signing-key"
})

test_user {
  allow with input as {
    "token": admin_token,
    "route": "/user"
  }
}