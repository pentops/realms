package authtest

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/pentops/j5/gen/j5/auth/v1/auth_j5pb"
	"github.com/pentops/j5/gen/j5/messaging/v1/messaging_j5pb"
	"github.com/pentops/realms/j5auth"
	"google.golang.org/grpc/metadata"
)

type tokenOption func(*j5auth.JWT)

func WithActorTags(tags map[string]string) tokenOption {
	return func(token *j5auth.JWT) {
		token.ActorTags = tags
	}
}

func WithScopes(scopes []string) tokenOption {
	return func(token *j5auth.JWT) {
		token.Scopes = scopes
	}
}

func WithSubject(subjectType, subjectID string) tokenOption {
	return func(token *j5auth.JWT) {
		token.Subject = fmt.Sprintf("%s/%s", subjectType, subjectID)
	}
}

func WithClaim(claim *auth_j5pb.Claim) tokenOption {
	return func(token *j5auth.JWT) {
		token.TenantType = claim.TenantType
		token.TenantID = claim.TenantId
		token.RealmID = claim.RealmId
		token.Scopes = claim.Scopes
	}
}

func ActionContext(ctx context.Context, opts ...tokenOption) context.Context {
	token := buildToken(opts...)
	actor, err := j5auth.ActorFromJWT(token)
	if err != nil {
		panic(err)
	}

	action := &auth_j5pb.Action{
		Actor:  actor,
		Method: "/fake/method",
	}

	return j5auth.WithAction(ctx, action)
}

type messageOption func(*messaging_j5pb.MessageCause)

func WithMessageID(id string) messageOption {
	return func(cause *messaging_j5pb.MessageCause) {
		cause.MessageId = id
	}
}

func WithMessageSource(app, env string) messageOption {
	return func(cause *messaging_j5pb.MessageCause) {
		cause.SourceApp = app
		cause.SourceEnv = env
	}
}

func MessageContext(ctx context.Context, mods ...messageOption) context.Context {
	cause := &messaging_j5pb.MessageCause{
		Method:    "/fake/method",
		MessageId: uuid.NewString(),
		SourceApp: "source-app",
		SourceEnv: "source-env",
	}

	for _, mod := range mods {
		mod(cause)
	}

	return j5auth.WithMessageCause(ctx, cause)
}

func buildToken(opts ...tokenOption) *j5auth.JWT {

	token := &j5auth.JWT{
		ID:         uuid.New().String(),
		Issuer:     "test",
		Audience:   j5auth.StringOrSlice{"test"},
		Subject:    fmt.Sprintf("test/%s", uuid.NewString()),
		IssuedAt:   time.Now().Unix(),
		Expires:    time.Now().Add(time.Hour).Unix(),
		NotBefore:  time.Now().Unix(),
		Scopes:     []string{},
		TenantType: "test",
		TenantID:   uuid.NewString(),
		RealmID:    uuid.NewString(),
	}

	for _, opt := range opts {
		opt(token)
	}
	return token

}
func JWTContext(ctx context.Context, opts ...tokenOption) context.Context {
	token := buildToken(opts...)

	jwtJSON, err := json.Marshal(token)
	if err != nil {
		panic(err)
	}

	md := metadata.MD{j5auth.VerifiedJWTHeader: []string{
		string(jwtJSON),
	}}

	ctx = metadata.NewOutgoingContext(ctx, md)
	return ctx
}
