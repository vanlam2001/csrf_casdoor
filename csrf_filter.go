package routers

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/beego/beego/v2/server/web/context"
)

func CSRFFilter(ctx *context.Context) {
	switch ctx.Request.Method {
	case http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch:
	default:
		return
	}

	// Header-based auth: browsers can't attach this cross-site without CORS preflight
	if ctx.Request.Header.Get("Authorization") != "" {
		return
	}

	// No session cookie => no ambient credential to abuse
	if _, err := ctx.Request.Cookie("casdoor_session_id"); err != nil {
		return
	}

	// Session cookie present: require same-origin
	src := ctx.Request.Header.Get("Origin")
	if src == "" {
		src = ctx.Request.Header.Get("Referer")
	}
	if src == "" || src == "null" || !isSameHost(src, ctx.Request.Host) {
		ctx.ResponseWriter.WriteHeader(http.StatusForbidden)
		responseError(ctx, T(ctx, "auth:Unauthorized operation"), "CSRF check failed")
	}
}

func isSameHost(source, reqHost string) bool {
	u, err := url.Parse(source)
	if err != nil || u.Hostname() == "" {
		return false
	}
	return strings.EqualFold(u.Hostname(), removePort(reqHost))
}
