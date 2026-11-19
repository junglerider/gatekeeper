package client

import (
	"context"
	"junglerider/gatekeeper/auth"
	clientpb "junglerider/gatekeeper/client/pb"

	"github.com/rs/zerolog/log"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

type GRPCAuthServer struct {
	clientpb.UnimplementedAuthServiceServer
	controller *Controller
}

func NewGRPCAuthServer(controller *Controller) *GRPCAuthServer {
	return &GRPCAuthServer{controller: controller}
}

func (s *GRPCAuthServer) Auth(_ context.Context, request *clientpb.AuthRequest) (*clientpb.AuthResponse, error) {
	if request == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	realm := s.controller.DefaultRealm(request.GetRealm())
	if err := s.controller.ValidateRealm(realm); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if request.GetToken() == "" {
		return nil, status.Error(codes.InvalidArgument, "token is required for authentication")
	}
	claims, err := verifyClientAccessToken(request.GetToken(), realm, s.controller.Config)
	if err != nil {
		clientID, _ := auth.UnverifiedTokenIdentity(request.GetToken())
		tokenAuthFailureEvent(err).
			Str("realm", realm).
			Str("client_id", clientID).
			Msg("access token authentication failed")
		return nil, status.Error(codes.Unauthenticated, "invalid or expired access token")
	}
	claimsStruct, err := structpb.NewStruct(map[string]any(claims))
	if err != nil {
		log.Error().Err(err).Msg("unable to encode token claims")
		return nil, status.Error(codes.Internal, "unable to encode token claims")
	}
	return &clientpb.AuthResponse{Claims: claimsStruct}, nil
}
