package rbac

import input

token = {"header": header, "payload": payload, "signature": signature} { io.jwt.decode(input.token, [header, payload, signature]) }

default allow = false
timenowns := time.now_ns()
timeclock := time.clock(timenowns)
isAdmin:= token.payload.roles[_] == "admin"
isUser:= token.payload.roles[_] == "user"

allow {
  isAdmin
}

allow {
  isUser
  some i
  glob.match(data.authorization_rules[i].route, [], input.route)
  data.authorization_rules[i].roles[_] == token.payload.roles[_]
  input.operation == "GET"
}

allow {
  isUser
  some i
  glob.match(data.authorization_rules[i].route, [], input.route)
  data.authorization_rules[i].roles[_] == token.payload.roles[_]
  timeclock[0] >= 8
  timeclock[0] < 17
}