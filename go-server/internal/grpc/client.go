package grpc

import (
	protos "github.com/codeshaine/go-server-template/internal/grpc/protos/generated"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func NewGreeterClient(conn string) (protos.GreeterClient, error) {

	connection, err := grpc.NewClient(conn, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}

	return protos.NewGreeterClient(connection), nil
}
