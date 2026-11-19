package user

import (
	"context"
	"net"
	"testing"

	"junglerider/gatekeeper/app"
	userpb "junglerider/gatekeeper/user/pb"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

func TestGRPCAuth(t *testing.T) {
	controller := &Controller{
		BaseController: &app.BaseController{Config: setupTestConfig()},
	}
	tokenPair := setupTokenPair(t)

	listener := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	userpb.RegisterAuthServiceServer(server, NewGRPCAuthServer(controller))
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

	rpcClient := userpb.NewAuthServiceClient(conn)
	response, err := rpcClient.Auth(context.Background(), &userpb.AuthRequest{
		Token: tokenPair.AccessToken,
		Realm: "test",
	})
	require.NoError(t, err)
	require.NotNil(t, response.GetClaims())
	require.Equal(t, "client1", response.GetClaims().AsMap()["client_id"])
	require.Equal(t, "user1", response.GetClaims().AsMap()["sub"])

	_, err = rpcClient.Auth(context.Background(), &userpb.AuthRequest{
		Token: "invalid-token",
		Realm: "test",
	})
	require.Equal(t, codes.Unauthenticated, status.Code(err))

	_, err = rpcClient.Auth(context.Background(), &userpb.AuthRequest{
		Token: tokenPair.AccessToken,
		Realm: "unknown-realm",
	})
	require.Equal(t, codes.InvalidArgument, status.Code(err))

	_, err = rpcClient.Auth(context.Background(), &userpb.AuthRequest{
		Realm: "test",
	})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
}
