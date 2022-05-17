package rbac

import input

# io.jwt.decode takes one argument (the encoded token) and has three outputs:
# the decoded header, payload and signature, in that order. Our policy only
# cares about the payload, so we ignore the others.
token = {"header": header, "payload": payload, "signature": signature} { io.jwt.decode(input.token, [header, payload, signature]) }

# By default, we deny the request
default allow = false

route = input.route

allow {
  roles = data.policy.route[policy_route]
  regex.match(policy_route, request_route)
  roles[_] == token.roles[_]
}
