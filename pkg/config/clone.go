package config

func defaultValue[T any](value *T, fallback T) *T {
	if value == nil {
		return &fallback
	}
	c := *value
	return &c
}

func cloneSlice[T any](values []T, clone func(T) T) []T {
	if values == nil {
		return nil
	}
	cloned := make([]T, len(values))
	for index, value := range values {
		cloned[index] = clone(value)
	}
	return cloned
}

func cloneConfigPointer[T any](value *T, clone func(T) T) *T {
	if value == nil {
		return nil
	}
	cloned := clone(*value)
	return &cloned
}

func clonePointer[T any](value *T) *T {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}
