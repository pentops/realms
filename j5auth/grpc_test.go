package j5auth

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

func TestGRPCMiddleware(t *testing.T) {
	runMiddleware(t, "/foo.v1.Foo/Bar", metadata.MD{}, func(ctx context.Context) {
		action := GetAction(ctx)
		if action == nil {
			t.Fatal("expected non-nil action")
		}
		if action.Method != "/foo.v1.Foo/Bar" {
			t.Fatalf("unexpected method: %s", action.Method)
		}
		if action.Actor != nil {
			t.Fatal("expected nil actor")
		}
	})

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
