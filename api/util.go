package api

func String(in string) *string {
	ret := new(string)
	*ret = in
	return ret
}

func Int(in int64) *int64 {
	ret := new(int64)
	*ret = in
	return ret
}
