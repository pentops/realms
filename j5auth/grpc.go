package j5auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/grpc-ecosystem/go-grpc-middleware/v2/metadata"
	"github.com/pentops/j5/gen/j5/auth/v1/auth_j5pb"
	"github.com/pentops/j5/gen/j5/messaging/v1/messaging_j5pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	VerifiedJWTHeader    = "x-verified-jwt"
	O5MessageCauseHeader = "x-o5-message-cause"
)

type controllerContextKey struct{}

type controllerContext struct {
	Action  *auth_j5pb.Action
	Message *messaging_j5pb.MessageCause
}

// WithAction should only be used in test cases, otherwise use the GRPCMiddleware.
func WithAction(ctx context.Context, action *auth_j5pb.Action) context.Context {
	return withControllerContext(ctx, &controllerContext{
		Action: action,
	})
}

// WithMessageCause should only be used in test cases, otherwise use the
// GRPCMiddleware.
func WithMessageCause(ctx context.Context, message *messaging_j5pb.MessageCause) context.Context {
	return withControllerContext(ctx, &controllerContext{
		Message: message,
	})
}

var ErrNoActor = status.Error(codes.Unauthenticated, "no actor in context")

func GetAction(ctx context.Context) *auth_j5pb.Action {
	cc := getControllerContext(ctx)
	if cc == nil {
		return nil
	}
	return cc.Action // may be nil
}

func withControllerContext(ctx context.Context, action *controllerContext) context.Context {
	return context.WithValue(ctx, controllerContextKey{}, action)
}

func getControllerContext(ctx context.Context) *controllerContext {
	if cc, ok := ctx.Value(controllerContextKey{}).(*controllerContext); ok {
		return cc
	}
	return nil
}

func GetAuthenticatedAction(ctx context.Context) (*auth_j5pb.Action, error) {
	cc := getControllerContext(ctx)
	if cc == nil || cc.Action == nil {
		return nil, errors.New("no action in context")
	}
	if cc.Action.Actor == nil {
		return nil, ErrNoActor
	}
	return cc.Action, nil
}

func GetMessageCause(ctx context.Context) (*messaging_j5pb.MessageCause, error) {
	cc := getControllerContext(ctx)
	if cc == nil || cc.Message == nil {
		return nil, errors.New("no message cause in context")
	}
	return cc.Message, nil
}

func GRPCMiddleware(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	cc := &controllerContext{}

	md := metadata.ExtractIncoming(ctx)

	jwt, err := getSidecarJWT(md)
	if err != nil {
		return nil, err
	}

	if jwt != nil {
		actor, err := ActorFromJWT(jwt)
		if err != nil {
			return nil, err
		}

		cc.Action = &auth_j5pb.Action{
			Method: info.FullMethod,
			Actor:  actor,
		}
	}

	messageCause, err := getMessageCause(md)
	if err != nil {
		return nil, err
	}

	if messageCause != nil {
		cc.Message = &messaging_j5pb.MessageCause{
			Method:    info.FullMethod,
			MessageId: messageCause.MessageId,
			SourceApp: messageCause.SourceApp,
			SourceEnv: messageCause.SourceEnv,
		}
	}

	ctx = withControllerContext(ctx, cc)

	return handler(ctx, req)
}

func getSidecarJWT(incomingMD metadata.MD) (*JWT, error) {
	verifiedJWT := incomingMD.Get(VerifiedJWTHeader)
	if verifiedJWT == "" {
		return nil, nil
	}

	var authJWT *JWT
	err := json.Unmarshal([]byte(verifiedJWT), &authJWT)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal verified JWT: %w", err)
	}

	return authJWT, nil
}

func getMessageCause(md metadata.MD) (*messaging_j5pb.MessageCauseHeader, error) {
	cause := md.Get(O5MessageCauseHeader)
	if cause == "" {
		return nil, nil
	}

	messageCause := &messaging_j5pb.MessageCauseHeader{}

	err := protojson.Unmarshal([]byte(cause), messageCause)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal message cause: %w", err)
	}

	return messageCause, nil
}
