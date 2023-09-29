package authmethods

func (am *AuthMethod) FilterValue() string {
	if am.Name != "" {
		return am.Name
	}
	return am.Id
}
