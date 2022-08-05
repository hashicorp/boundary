function login() {
  export BP="${DEFAULT_PASSWORD}"
  boundary authenticate password -auth-method-id $DEFAULT_AMPW -login-name $1 -password env://BP
}
