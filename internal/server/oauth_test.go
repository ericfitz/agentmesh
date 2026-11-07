package server

import (
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/ericfitz/agentmesh/internal/bus"
	"github.com/ericfitz/agentmesh/internal/core"
	"github.com/ericfitz/agentmesh/internal/gen"
)

func TestOAuthFromBus(t *testing.T) {
	cases := []struct {
		code     bus.Code
		exchange bool
		status   int
		want     string
	}{
		{bus.CodeUnauthenticated, false, http.StatusUnauthorized, "invalid_client"},
		{bus.CodeValidation, false, http.StatusBadRequest, "invalid_request"},
		{bus.CodeForbidden, false, http.StatusInternalServerError, "server_error"},
		{bus.CodeConflict, false, http.StatusInternalServerError, "server_error"},
		{bus.CodeForbidden, true, http.StatusBadRequest, exchangeDeniedCode},
		{bus.CodeUnauthenticated, true, http.StatusBadRequest, "invalid_request"},
		{bus.CodeConflict, true, http.StatusBadRequest, "invalid_request"},
		{bus.CodeValidation, true, http.StatusBadRequest, "invalid_request"},
		{bus.CodeUnavailable, false, http.StatusServiceUnavailable, "temporarily_unavailable"},
		{bus.CodeUnavailable, true, http.StatusServiceUnavailable, "temporarily_unavailable"},
		{bus.CodeInternal, true, http.StatusInternalServerError, "server_error"},
		{bus.CodeNotFound, false, http.StatusInternalServerError, "server_error"},
	}
	for _, tc := range cases {
		got := oauthFromBus(core.E(tc.code, "detail"), tc.exchange)
		if got.Status != tc.status || got.Code != tc.want {
			t.Errorf("%s exchange=%v: got %d %s, want %d %s", tc.code, tc.exchange, got.Status, got.Code, tc.status, tc.want)
		}
	}
	// A server_error never carries the underlying text.
	if got := oauthFromBus(errors.New("db password=hunter2"), false); got.Code != "server_error" || got.Description != "internal error" {
		t.Errorf("plain error: %+v", got)
	}
}

// TestTokenFormFieldsComplete fails when gen.TokenRequest gains a string member
// that tokenFormFields does not bound.
func TestTokenFormFieldsComplete(t *testing.T) {
	listed := map[string]bool{}
	for _, f := range tokenFormFields(&gen.TokenRequest{}) {
		listed[f.name] = true
	}
	rt := reflect.TypeOf(gen.TokenRequest{})
	for i := range rt.NumField() {
		ft := rt.Field(i).Type
		if ft.Kind() == reflect.Pointer {
			ft = ft.Elem()
		}
		if ft.Kind() != reflect.String {
			t.Errorf("%s is not a string: bound it in tokenFormFields", rt.Field(i).Name)
			continue
		}
		name, _, _ := strings.Cut(rt.Field(i).Tag.Get("json"), ",")
		if !listed[name] {
			t.Errorf("TokenRequest.%s (%s) has no bound in tokenFormFields", rt.Field(i).Name, name)
		}
		delete(listed, name)
	}
	for name := range listed {
		t.Errorf("tokenFormFields lists %q, which TokenRequest does not have", name)
	}
}
