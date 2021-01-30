function login() {
  boundary authenticate password -auth-method-id $DEFAULT_AMPW -login-name $1 -password $DEFAULT_PASSWORD
}
