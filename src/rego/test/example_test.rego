package rbac

admin_token := io.jwt.encode_sign({
  "typ": "JWT",
  "alg": "HS256"
}, {
  "roles": {
    "admin"
  }
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