# # Note that this is an example config file and is not intended to be functional as-is.
# # Full configuration options can be found at https://www.boundaryproject.io/docs/configuration/worker

# listener "tcp" {
#     purpose = "proxy"
#     tls_disable = true
#     address = "127.0.0.1"
# }

# worker {
#   # Name attr must be unique across workers
#   name = "demo-worker-1"
#   description = "A default worker created demonstration"

#   # Workers must be able to reach controllers on :9201
#   initial_upstreams = [
#     "10.0.0.1",
#     "10.0.0.2",
#     "10.0.0.3",
#   ]

#   public_addr = "myhost.mycompany.com"

#   tags {
#     type   = ["prod", "webservers"]
#     region = ["us-east-1"]
#   }
# }

# # must be same key as used on controller config
# kms "aead" {
#     purpose = "worker-auth"
#     aead_type = "aes-gcm"
#     key = "8fZBjCUfN0TzjEGLQldGY4+iE9AkOvCfjh7+p0GtRBQ="
#     key_id = "global_worker-auth"
# }
