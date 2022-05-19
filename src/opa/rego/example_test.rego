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

user_token := io.jwt.encode_sign({
  "typ": "JWT",
  "alg": "HS256"
}, {
  "roles": ["user"]
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
test_speakers_admin_true {
  allow with input as {
    "token": admin_token,
    "route": "/speakers",
    "operation": "GET"
  }
}

test_sessions_admin_true {
  allow with input as {
    "token": admin_token,
    "route": "/sessions",
    "operation": "GET"
  }
}

test_topics_admin_true {
  allow with input as {
    "token": admin_token,
    "route": "/topics",
    "operation": "GET"
  }
}

test_speakers_user_false {
  not allow with input as {
    "token": user_token,
    "route": "/speakers",
    "operation": "GET"
  }
}

test_speakers_empty_false {
  not allow with input as {
    "token": empty_token,
    "route": "/speakers",
    "operation": "GET"
  }
}

test_sessions_user_true {
  allow with input as {
    "token": user_token,
    "route": "/sessions",
    "operation": "GET"
  }
}

test_sessions_user_post_false {
  not allow with input as {
    "token": user_token,
    "route": "/sessions",
    "operation": "POST"
  }
}

test_topics_user_true {
  allow with input as {
    "token": user_token,
    "route": "/topics",
    "operation": "GET"
  }
}

test_topics_id_users_true {
  allow with input as {
    "token": user_token,
    "route": "/topics/1234",
    "operation": "GET"
  }
}
