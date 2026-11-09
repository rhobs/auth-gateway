package main

import (
	"context"
	"crypto/tls"
	"log"
	"net"
	"strings"
	"time"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	envoytype "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

type server struct {
	authv3.UnimplementedAuthorizationServer
}

func (server) Check(ctx context.Context, request *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	attributes := request.GetAttributes()
	headers := attributes.GetRequest().GetHttp().GetHeaders()
	mode := header(headers, "x-policy-mode")
	if mode == "error" {
		return nil, status.Error(codes.Unavailable, "test policy failure")
	}
	if mode == "timeout" {
		select {
		case <-time.After(2 * time.Second):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	requested := header(headers, "x-tenant")
	route := attributes.GetRouteMetadataContext().GetFilterMetadata()["auth_gateway.ext_authz.access"]
	if route.GetFields()["api"].GetStringValue() != "ext-authz-api" {
		return deny(envoytype.StatusCode_Forbidden), nil
	}
	access := route.GetFields()["access"].GetStringValue()
	switch access {
	case "jwt":
		claims := attributes.GetMetadataContext().GetFilterMetadata()["envoy.filters.http.jwt_authn"].GetFields()["issuer-one"].GetStructValue().GetFields()
		tenant := claims["organization"].GetStructValue().GetFields()["id"].GetStringValue()
		if tenant != requested || requested != "internal" {
			return deny(envoytype.StatusCode_Forbidden), nil
		}
		return allow(requested, mode), nil
	case "external":
		if header(headers, "authorization") != "Bearer e2e-partner" {
			return deny(envoytype.StatusCode_Unauthorized), nil
		}
		if requested != "partner" {
			return deny(envoytype.StatusCode_Forbidden), nil
		}
		return allow(requested, mode), nil
	default:
		return deny(envoytype.StatusCode_Forbidden), nil
	}
}

func header(headers map[string]string, name string) string {
	for key, value := range headers {
		if strings.EqualFold(key, name) {
			return value
		}
	}
	return ""
}

func allow(tenant, mode string) *authv3.CheckResponse {
	identity := map[string]any{"tenant": tenant, "subject": "e2e-subject"}
	switch mode {
	case "missing-attribute":
		delete(identity, "tenant")
	case "list-attribute":
		identity["tenant"] = []string{tenant}
	}
	metadata, _ := structpb.NewStruct(map[string]any{"identity": identity})
	ok := &authv3.OkHttpResponse{}
	if mode == "mutation" {
		ok.Headers = []*core.HeaderValueOption{{Header: &core.HeaderValue{Key: "x-scope-orgid", Value: "spoofed"}}}
	}
	return &authv3.CheckResponse{Status: status.New(codes.OK, "").Proto(), DynamicMetadata: metadata,
		HttpResponse: &authv3.CheckResponse_OkResponse{OkResponse: ok}}
}

func deny(code envoytype.StatusCode) *authv3.CheckResponse {
	return &authv3.CheckResponse{Status: status.New(codes.PermissionDenied, "test denial").Proto(),
		HttpResponse: &authv3.CheckResponse_DeniedResponse{DeniedResponse: &authv3.DeniedHttpResponse{Status: &envoytype.HttpStatus{Code: code}}}}
}

func main() {
	certificate, err := tls.LoadX509KeyPair("/tls/tls.crt", "/tls/tls.key")
	if err != nil {
		log.Fatal(err)
	}
	listener, err := net.Listen("tcp", ":9000")
	if err != nil {
		log.Fatal(err)
	}
	grpcServer := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})))
	authv3.RegisterAuthorizationServer(grpcServer, server{})
	log.Fatal(grpcServer.Serve(listener))
}
