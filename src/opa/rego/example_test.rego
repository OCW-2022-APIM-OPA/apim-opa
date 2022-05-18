package rbac

admin_token := io.jwt.encode_sign({
  "typ": "JWT",
  "alg": "HS256"
}, {
  "sub": "1234567890",
  "name": "John Doe",
  "iat": 1516239022,
  "roles": [
    "admin",
    "reader"
  ]
}, {
  "kty": "oct",
  "k": "test-signing-key"
})

test_user {
  allow with input as {
    "token": admin_token,
    "route": "/user"
  }
}