//nolint
package main

import (
	"net/http"
	urlpkg "net/url"
	"path"
	"strconv"
	"strings"
	"unicode/utf8"

	"net/textproto"

	"github.com/http-wasm/http-wasm-guest-tinygo/handler/api"
	"golang.org/x/net/http/httpguts"
)

// Redirect replies to the request with a redirect to url,
// which may be a path relative to the request path.
//
// The provided code should be in the 3xx range and is usually
// [StatusMovedPermanently], [StatusFound] or [StatusSeeOther].
//
// If the Content-Type header has not been set, [Redirect] sets it
// to "text/html; charset=utf-8" and writes a small HTML body.
// Setting the Content-Type header to any value, including nil,
// disables that behavior.
func Redirect(r api.Request, w api.Response, url string, code int) {
	if u, err := urlpkg.Parse(url); err == nil {
		// If url was relative, make its path absolute by
		// combining with request path.
		// The client would probably do this for us,
		// but doing it ourselves is more reliable.
		// See RFC 7231, section 7.1.2
		if u.Scheme == "" && u.Host == "" {
			oldpath := r.GetURI()
			if oldpath == "" { // should not happen, but avoid a crash if it does
				oldpath = "/"
			}

			// no leading http://server
			if url == "" || url[0] != '/' {
				// make relative path absolute
				olddir, _ := path.Split(oldpath)
				url = olddir + url
			}

			var query string
			if i := strings.Index(url, "?"); i != -1 {
				url, query = url[:i], url[i:]
			}

			// clean up but preserve trailing slash
			trailing := strings.HasSuffix(url, "/")
			url = path.Clean(url)
			if trailing && !strings.HasSuffix(url, "/") {
				url += "/"
			}
			url += query
		}
	}

	h := w.Headers()

	// RFC 7231 notes that a short HTML body is usually included in
	// the response because older user agents may not understand 301/307.
	// Do it only if the request didn't already have a Content-Type header.
	_, hadCT := h.Get("Content-Type")

	h.Set("Location", hexEscapeNonASCII(url))
	if !hadCT && (r.GetMethod() == "GET" || r.GetMethod() == "HEAD") {
		h.Set("Content-Type", "text/html; charset=utf-8")
	}
	w.SetStatusCode(uint32(code))

	// Shouldn't send the body for POST or HEAD; that leaves GET.
	if !hadCT && r.GetMethod() == "GET" {
		body := "<a href=\"" + htmlEscape(url) + "\">" + http.StatusText(code) + "</a>.\n"
		w.Body().WriteString(body)
	}
}

func hexEscapeNonASCII(s string) string {
	newLen := 0
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			newLen += 3
		} else {
			newLen++
		}
	}
	if newLen == len(s) {
		return s
	}
	b := make([]byte, 0, newLen)
	var pos int
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			if pos < i {
				b = append(b, s[pos:i]...)
			}
			b = append(b, '%')
			b = strconv.AppendInt(b, int64(s[i]), 16)
			pos = i + 1
		}
	}
	if pos < len(s) {
		b = append(b, s[pos:]...)
	}
	return string(b)
}

var htmlReplacer = strings.NewReplacer(
	"&", "&amp;",
	"<", "&lt;",
	">", "&gt;",
	// "&#34;" is shorter than "&quot;".
	`"`, "&#34;",
	// "&#39;" is shorter than "&apos;" and apos was not in HTML until HTML5.
	"'", "&#39;",
)

func htmlEscape(s string) string {
	return htmlReplacer.Replace(s)
}

// SetCookie adds a Set-Cookie header to the provided [ResponseWriter]'s headers.
// The provided cookie must have a valid Name. Invalid cookies may be
// silently dropped.
func SetCookie(w api.Response, cookie *http.Cookie) {
	if v := cookie.String(); v != "" {
		w.Headers().Add("Set-Cookie", v)
	}
}

func GetCookie(req api.Request, name string) (*http.Cookie, error) {
	if name == "" {
		return nil, http.ErrNoCookie
	}
	for _, c := range ReadCookies(req.Headers(), name) {
		return c, nil
	}
	return nil, http.ErrNoCookie
}

func ReadCookies(header api.Header, filter string) []*http.Cookie {
	lines := header.GetAll("Cookie")
	if len(lines) == 0 {
		return []*http.Cookie{}
	}

	cookies := make([]*http.Cookie, 0, len(lines)+strings.Count(lines[0], ";"))
	for _, line := range lines {
		line = textproto.TrimString(line)

		var part string
		for len(line) > 0 { // continue since we have rest
			part, line, _ = strings.Cut(line, ";")
			part = textproto.TrimString(part)
			if part == "" {
				continue
			}
			name, val, _ := strings.Cut(part, "=")
			name = textproto.TrimString(name)
			if !isCookieNameValid(name) {
				continue
			}
			if filter != "" && filter != name {
				continue
			}
			val, ok := parseCookieValue(val, true)
			if !ok {
				continue
			}
			cookies = append(cookies, &http.Cookie{Name: name, Value: val})
		}
	}
	return cookies
}

func isCookieNameValid(raw string) bool {
	if raw == "" {
		return false
	}
	return strings.IndexFunc(raw, isNotToken) < 0
}

func isNotToken(r rune) bool {
	return !httpguts.IsTokenRune(r)
}

func parseCookieValue(raw string, allowDoubleQuote bool) (string, bool) {
	// Strip the quotes, if present.
	if allowDoubleQuote && len(raw) > 1 && raw[0] == '"' && raw[len(raw)-1] == '"' {
		raw = raw[1 : len(raw)-1]
	}
	for i := 0; i < len(raw); i++ {
		if !validCookieValueByte(raw[i]) {
			return "", false
		}
	}
	return raw, true
}

func validCookieValueByte(b byte) bool {
	return 0x20 <= b && b < 0x7f && b != '"' && b != ';' && b != '\\'
}

func HttpError(w api.Response, error string, code int) {
	w.Headers().Set("Content-Type", "text/plain; charset=utf-8")
	w.Headers().Set("X-Content-Type-Options", "nosniff")
	w.SetStatusCode(uint32(code))
	w.Body().WriteString(error)
}
