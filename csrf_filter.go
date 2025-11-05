package routers

import (
	"net/http"
	"strings"

	"github.com/beego/beego/context"
)

// CSRFFilter denies cross-site, cookie-based state-changing requests under /api/*.
// Allows cross-origin if explicit auth is present (Authorization/Basic/client credentials/accessToken)
// or if no session cookie is involved (server-to-server without browser cookies).
func CSRFFilter(ctx *context.Context) {
	// Only guard state-changing methods globally under /api/*
	method := ctx.Request.Method
	if method != http.MethodPost && method != http.MethodPut && method != http.MethodDelete && method != http.MethodPatch {
		return
	}
	if !strings.HasPrefix(ctx.Request.URL.Path, "/api/") {
		return
	}

	// Allow if request carries explicit non-cookie auth
	if hasAuthIndicators(ctx) {
		return
	}

	origin := ctx.Request.Header.Get("Origin")
	referer := ctx.Request.Header.Get("Referer")
	host := removePort(ctx.Request.Host)

	// Determine session cookie presence
	hasSession := false
	if _, err := ctx.Request.Cookie("casdoor_session_id"); err == nil {
		hasSession = true
	} else if cookieHeader := ctx.Request.Header.Get("Cookie"); strings.Contains(cookieHeader, "casdoor_session_id=") {
		hasSession = true
	}

	if origin == "" && referer == "" {
		// No origin/referer; if no session cookies, not CSRF -> allow
		if hasSession {
			responseError(ctx, T(ctx, "auth:Unauthorized operation"), "CSRF check failed")
		}
		return
	}

	sameOrigin := false
	if origin != "" {
		sameOrigin = getHostname(origin) == host
	} else {
		sameOrigin = getHostname(referer) == host
	}

	if !sameOrigin && hasSession {
		// Block cross-site only when cookies are present
		responseError(ctx, T(ctx, "auth:Unauthorized operation"), "CSRF check failed")
		return
	}
}

// hasAuthIndicators returns true if request carries explicit, non-cookie auth
func hasAuthIndicators(ctx *context.Context) bool {
	if ctx.Request.Header.Get("Authorization") != "" {
		return true
	}
	if _, _, ok := ctx.Request.BasicAuth(); ok {
		return true
	}
	if ctx.Input.Query("accessToken") != "" || ctx.Input.Query("access_token") != "" {
		return true
	}
	if (ctx.Input.Query("clientId") != "" && ctx.Input.Query("clientSecret") != "") ||
		(ctx.Input.Query("client_id") != "" && ctx.Input.Query("client_secret") != "") {
		return true
	}
	return false
}
