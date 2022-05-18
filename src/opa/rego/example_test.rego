package rbac

### Generate test tokens
admin_token := io.jwt.encode_sign({
  "typ": "JWT",
  "alg": "HS256"
}, {
  "roles": ["admin"]
}, {
  "kty": "oct",
  "k": "test-signing-key"
})

contributor_token := io.jwt.encode_sign({
  "typ": "JWT",
  "alg": "HS256"
}, {
  "roles": ["contributor"]
}, {
  "kty": "oct",
  "k": "test-signing-key"
})

empty_token := io.jwt.encode_sign({
  "typ": "JWT",
  "alg": "HS256"
}, {
  "roles": []
}, {
  "kty": "oct",
  "k": "test-signing-key"
})

### Execute tests
test_speakers_true {
  allow with input as {
    "token": admin_token,
    "route": "/conference/speakers",
    "operation": "GET"
  }
}

test_speakers_false {
  not allow with input as {
    "token": empty_token,
    "route": "/conference/speakers",
    "operation": "GET"
  }
}

test_sessions_true {
  allow with input as {
    "token": contributor_token,
    "route": "/conference/sessions",
    "operation": "GET"
  }
}

test_sessions_false {
  not allow with input as {
    "token": admin_token,
    "route": "/conference/sessions",
    "operation": "GET"
  }
}

test_topics_true {
  allow with input as {
    "token": admin_token,
    "route": "/conference/topics",
    "operation": "GET"
  }
}

test_topics_false {
  not allow with input as {
    "token": admin_token,
    "route": "/conference/topics/1234",
    "operation": "GET"
  }
}
