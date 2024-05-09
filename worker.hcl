// worker.hcl
 listener "tcp" {
    purpose = "proxy"
    tls_disable = true
    address = "0.0.0.0"
    
}

worker {
  name = "worker-01"
  controllers = [
    "127.0.0.1"
  ]
  
  // change this with your ip public instance
  public_addr = "13.229.x.x"
}

# must be same key as used on controller config
kms "aead" {
    purpose   = "worker-auth"
    aead_type = "aes-gcm"
    key       = "8fZBjCUfN0TzjEGLQldGY4+iE9AkOvCfjh7+p0GtRBQ="
    key_id    = "global_worker-auth"
}
