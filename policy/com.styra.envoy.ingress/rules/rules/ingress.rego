package policy["com.styra.envoy.ingress"].rules.rules

import input.attributes.request.http as http_request
import input.parsed_path

default allow = false


# allow health checks of the opa sidecar
allow {
    parsed_path[0] == "health"
    http_request.method == "POST"
}

allow {
	is_get
	claims.role == "Admin"
}

is_get {
	input.attributes.request.http.method == "GET"
}



claims := payload {

	# This statement invokes the built-in function `io.jwt.decode` passing the
	# parsed bearer_token as a parameter. The `io.jwt.decode` function returns an
	# array:
	#
	#	[header, payload, signature]
	#
	# In Rego, you can pattern match values using the `=` and `:=` operators. This
	# example pattern matches on the result to obtain the JWT payload.
	[_, payload, _] := io.jwt.decode(bearer_token)
}

bearer_token := t {
	# Bearer tokens are contained inside of the HTTP Authorization header. This rule
	# parses the header and extracts the Bearer token value. If no Bearer token is
	# provided, the `bearer_token` value is undefined.
	v := input.attributes.request.http.headers.authorization
	startswith(v, "Bearer ")
	t := substring(v, count("Bearer "), -1)
}
