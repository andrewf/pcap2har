process_pages = True
drop_bodies = False  # bodies of http responses, that is

# Whether HTTP parsing should case whether the content length matches the
# content-length header.
strict_http_parse_body = False

# Whether to pad missing data in TCP flows with 0 bytes
pad_missing_tcp_data = False

# Whether to keep requests with missing responses. Could break consumers
# that assume every request has a response.
keep_unfulfilled_requests = False

# Whether TLS packets should be parsed
process_tls = True
