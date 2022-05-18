package rbac

import input

token = {"header": header, "payload": payload, "signature": signature} { io.jwt.decode(input.input.token, [header, payload, signature]) }

default allow = false

allow {
  some i
  glob.match(data.authorization_rules[i].route, [], input.input.route)
  data.authorization_rules[i].roles[_] == token.payload.roles[_]
}
