package handler

import (
	"net/http"

	"github.com/scimsandbox/scim-server-impl-go/internal/scim"
)

type MeHandler struct{}

func NewMeHandler() *MeHandler {
	return &MeHandler{}
}

func (h *MeHandler) Handle(w http.ResponseWriter, _ *http.Request) {
	scim.WriteScimError(w, scim.NewScimError(http.StatusNotImplemented, "", "The /Me endpoint is not implemented"))
}
