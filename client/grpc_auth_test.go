package client

import (
	"context"
	"net"
	"testing"

	clientpb "junglerider/gatekeeper/client/pb"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

func TestGRPCAuthAuthenticate(t *testing.T) {
	controller, _, _ := setupTestController(t)
	tokenPair := setupTokenPair(t)

	listener := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	clientpb.RegisterAuthServiceServer(server, NewGRPCAuthServer(controller))
	go func() {
		_ = server.Serve(listener)
	}()
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
	})

	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return listener.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	rpcClient := clientpb.NewAuthServiceClient(conn)
	response, err := rpcClient.Auth(context.Background(), &clientpb.AuthRequest{
		Token: tokenPair.AccessToken,
		Realm: "test-realm",
	})
	require.NoError(t, err)
	require.NotNil(t, response.GetClaims())
	require.Equal(t, "client1", response.GetClaims().AsMap()["client_id"])
	require.Equal(t, "client", response.GetClaims().AsMap()["role"])

	_, err = rpcClient.Auth(context.Background(), &clientpb.AuthRequest{
		Token: "invalid-token",
		Realm: "test-realm",
	})
	require.Equal(t, codes.Unauthenticated, status.Code(err))

	_, err = rpcClient.Auth(context.Background(), &clientpb.AuthRequest{
		Token: tokenPair.AccessToken,
		Realm: "unknown-realm",
	})
	require.Equal(t, codes.InvalidArgument, status.Code(err))

	_, err = rpcClient.Auth(context.Background(), &clientpb.AuthRequest{
		Realm: "test-realm",
	})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
}
