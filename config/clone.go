package config

type cloneable[T any] interface {
	clone() T
}

func defaultValue[T any](value *T, fallback T) *T {
	if value == nil {
		return &fallback
	}
	c := *value
	return &c
}

func cloneSlice[T cloneable[T]](values []T) []T {
	if values == nil {
		return nil
	}
	cloned := make([]T, len(values))
	for index, value := range values {
		cloned[index] = value.clone()
	}
	return cloned
}

func cloneConfigPointer[T cloneable[T]](value *T) *T {
	if value == nil {
		return nil
	}
	cloned := (*value).clone()
	return &cloned
}

func clonePointer[T any](value *T) *T {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}
