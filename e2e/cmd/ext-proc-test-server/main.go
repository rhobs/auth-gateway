package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extproc "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	envoytype "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type server struct {
	extproc.UnimplementedExternalProcessorServer
}

func (server) Process(stream extproc.ExternalProcessor_ProcessServer) error {
	var action string
	for {
		request, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		response := &extproc.ProcessingResponse{}
		switch {
		case request.GetRequestHeaders() != nil:
			headers := make(map[string]string)
			for _, h := range request.GetRequestHeaders().GetHeaders().GetHeaders() {
				headers[h.Key] = string(h.RawValue)
			}
			action = headers["x-processor-action"]
			if action == "error" {
				return status.Error(codes.Unavailable, "test processor failure")
			}
			if action == "reject" {
				response.Response = &extproc.ProcessingResponse_ImmediateResponse{ImmediateResponse: &extproc.ImmediateResponse{Status: &envoytype.HttpStatus{Code: envoytype.StatusCode_Forbidden}, Body: []byte("processor rejection")}}
			} else {
				input, err := json.Marshal(map[string]any{"metadata": request.GetMetadataContext().GetFilterMetadata(), "attributes": request.GetAttributes(), "headers": headers})
				if err != nil {
					return err
				}
				mutation := &extproc.HeaderMutation{SetHeaders: []*core.HeaderValueOption{setHeader("x-processed", "yes"), setHeader("x-processor-input", string(input))}}
				if action == "mutate" {
					mutation.SetHeaders = append(mutation.SetHeaders, setHeader(headers["x-processor-mutate"], "processor-value"))
				}
				if action == "path" {
					mutation.SetHeaders = append(mutation.SetHeaders, setHeader(":path", "/anything/processed?from=processor"))
				}
				response.Response = &extproc.ProcessingResponse_RequestHeaders{RequestHeaders: &extproc.HeadersResponse{Response: &extproc.CommonResponse{HeaderMutation: mutation, ClearRouteCache: action == "path"}}}
			}
		case request.GetRequestBody() != nil:
			body := bytes.ToUpper(request.GetRequestBody().Body)
			mutation := &extproc.BodyMutation{Mutation: &extproc.BodyMutation_Body{Body: body}}
			if action == "duplex" {
				mutation.Mutation = &extproc.BodyMutation_StreamedResponse{StreamedResponse: &extproc.StreamedBodyResponse{Body: body, EndOfStream: request.GetRequestBody().EndOfStream}}
			}
			response.Response = &extproc.ProcessingResponse_RequestBody{RequestBody: &extproc.BodyResponse{Response: &extproc.CommonResponse{BodyMutation: mutation}}}
		case request.GetRequestTrailers() != nil:
			response.Response = &extproc.ProcessingResponse_RequestTrailers{RequestTrailers: &extproc.TrailersResponse{}}
		default:
			return status.Error(codes.InvalidArgument, "unexpected response stage")
		}
		if err := stream.Send(response); err != nil {
			return err
		}
	}
}

func setHeader(name, value string) *core.HeaderValueOption {
	return &core.HeaderValueOption{Header: &core.HeaderValue{Key: name, RawValue: []byte(value)}}
}

func main() {
	listener, err := net.Listen("tcp", ":9000")
	if err != nil {
		log.Fatal(err)
	}
	grpcServer := grpc.NewServer()
	extproc.RegisterExternalProcessorServer(grpcServer, server{})
	log.Fatal(grpcServer.Serve(listener))
}
