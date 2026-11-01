package fail2ban_client

type Py_builtins_str struct{}

func (c Py_builtins_str) Call(args ...interface{}) (interface{}, error) {
	return args[0], nil
}
