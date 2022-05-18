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
test_users_true {
  allow with input as {
    "input": {
      "token": admin_token,
      "route": "/users",
      "operation": "GET"
    }
  }
}

test_users_false {
  not allow with input as {
    "input": {
      "token": empty_token,
      "route": "/users",
      "operation": "GET"
    }
  }
}

test_order_true {
  allow with input as {
    "input": {
      "token": contributor_token,
      "route": "/order",
      "operation": "GET"
    }
  }
}

test_order_false {
  not allow with input as {
    "input": {
      "token": admin_token,
      "route": "/order",
      "operation": "GET"
    }
  }
}

test_userFriends_true {
  allow with input as {
    "input": {
      "token": admin_token,
      "route": "/users/1234/friends",
      "operation": "GET"
    }
  }
}

test_userFriends_false {
  not allow with input as {
    "input": {
      "token": admin_token,
      "route": "/users/1234/strangers",
      "operation": "GET"
    }
  }
}
