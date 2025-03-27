package j5auth

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pentops/j5/gen/j5/messaging/v1/messaging_j5pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestGRPCMiddleware(t *testing.T) {
	t.Run("No Actor", func(t *testing.T) {
		runMiddleware(t, "/foo.v1.Foo/Bar", metadata.MD{}, func(ctx context.Context) {
			action := GetAction(ctx)
			if action != nil {
				t.Fatal("expected nil action")
			}
		})
	})

	t.Run("JWT Actor", func(t *testing.T) {
		runMiddleware(t, "/foo.v1.Foo/Bar", metadata.MD{
			VerifiedJWTHeader: []string{testToken(t, func(jwt *JWT) {
				jwt.TenantType = "tenant-type"
			})},
		}, func(ctx context.Context) {
			action := GetAction(ctx)
			if action == nil {
				t.Fatal("expected non-nil action")
			}
			if action.Method != "/foo.v1.Foo/Bar" {
				t.Fatalf("unexpected method: %s", action.Method)
			}
			if action.Actor == nil {
				t.Fatal("expected non-nil actor")
			}
			if action.Actor.Claim.TenantType != "tenant-type" {
				t.Fatalf("unexpected tenant type: %s", action.Actor.Claim.TenantType)
			}
		})
	})

	t.Run("Message Cause", func(t *testing.T) {

		cause := &messaging_j5pb.MessageCauseHeader{
			MessageId: uuid.NewString(),
			SourceApp: "source-app",
			SourceEnv: "source-env",
		}
		causeJSON, err := protojson.Marshal(cause)
		if err != nil {
			t.Fatal(err)
		}

		runMiddleware(t, "/foo.v1.Foo/Bar", metadata.MD{
			O5MessageCauseHeader: []string{string(causeJSON)},
		}, func(ctx context.Context) {
			action, err := GetMessageCause(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if action.MessageId != cause.MessageId {
				t.Fatalf("unexpected message id: %s", action.MessageId)
			}
			if action.SourceApp != cause.SourceApp {
				t.Fatalf("unexpected source app: %s", action.SourceApp)
			}
			if action.SourceEnv != cause.SourceEnv {
				t.Fatalf("unexpected source env: %s", action.SourceEnv)
			}
		})
	})
}

func testToken(t testing.TB, mods ...func(*JWT)) string {
	tt := &JWT{
		ID:         uuid.New().String(),
		Issuer:     "test",
		Audience:   StringOrSlice{"test"},
		Subject:    fmt.Sprintf("test/%s", uuid.NewString()),
		IssuedAt:   time.Now().Unix(),
		Expires:    time.Now().Add(time.Hour).Unix(),
		NotBefore:  time.Now().Unix(),
		Scopes:     []string{},
		TenantType: "test",
		TenantID:   uuid.NewString(),
		RealmID:    uuid.NewString(),
	}
	for _, mod := range mods {
		mod(tt)
	}
	data, err := json.Marshal(tt)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func runMiddleware(t testing.TB, method string, md metadata.MD, callback func(context.Context)) context.Context {
	ctx := metadata.NewIncomingContext(
		context.Background(),
		md,
	)

	_, err := GRPCMiddleware(ctx, nil, &grpc.UnaryServerInfo{
		FullMethod: method,
	}, func(ctx context.Context, req interface{}) (interface{}, error) {
		callback(ctx)
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return ctx
}
