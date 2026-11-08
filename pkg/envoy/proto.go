package envoy

import (
	"fmt"
	"time"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	gatewayapi "github.com/rhobs/auth-gateway/pkg/api"
	yaml "go.yaml.in/yaml/v3"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func protobufDuration(duration *gatewayapi.Duration) *durationpb.Duration {
	return durationpb.New(time.Duration(*duration))
}

type envoyValidator interface {
	ValidateAll() error
}

func optionalUint32(value *uint32) *wrapperspb.UInt32Value {
	if value == nil {
		return nil
	}
	return wrapperspb.UInt32(*value)
}

func socket(address string, port uint32) *core.Address {
	return &core.Address{Address: &core.Address_SocketAddress{SocketAddress: &core.SocketAddress{
		Address: address,
		PortSpecifier: &core.SocketAddress_PortValue{
			PortValue: port,
		},
	}}}
}

func packEnvoy(message proto.Message) (*anypb.Any, error) {
	if validatable, ok := message.(envoyValidator); ok {
		if err := validatable.ValidateAll(); err != nil {
			return nil, fmt.Errorf("validate %s: %w", message.ProtoReflect().Descriptor().FullName(), err)
		}
	}
	packed, err := anypb.New(message)
	if err != nil {
		return nil, fmt.Errorf("pack %s: %w", message.ProtoReflect().Descriptor().FullName(), err)
	}
	return packed, nil
}

func marshalEnvoyYAML(message proto.Message) ([]byte, error) {
	if validatable, ok := message.(envoyValidator); ok {
		if err := validatable.ValidateAll(); err != nil {
			return nil, fmt.Errorf("validate %s: %w", message.ProtoReflect().Descriptor().FullName(), err)
		}
	}
	data, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(message)
	if err != nil {
		return nil, fmt.Errorf("encode %s: %w", message.ProtoReflect().Descriptor().FullName(), err)
	}
	var value any
	if err := yaml.Unmarshal(data, &value); err != nil {
		return nil, fmt.Errorf("encode %s: convert JSON to YAML: %w", message.ProtoReflect().Descriptor().FullName(), err)
	}
	data, err = yaml.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("encode %s: marshal YAML: %w", message.ProtoReflect().Descriptor().FullName(), err)
	}
	return data, nil
}
