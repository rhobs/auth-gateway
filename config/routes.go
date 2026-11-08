package config

import (
	"fmt"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strings"

	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
)

const authorizationHeaderName = "authorization"

// Route describes the required methods and path matcher, plus optional rewrite and processing.
type Route struct {
	Methods    []string         `yaml:"methods"`
	Path       PathMatch        `yaml:"path"`
	Rewrite    *PathRewrite     `yaml:"rewrite,omitempty"`
	Processing *RouteProcessing `yaml:"processing,omitempty"`
	Timeouts   *RouteTimeouts   `yaml:"timeouts,omitempty"`
}

// PathMatch selects one exact path, path prefix, or safe regular expression.
type PathMatch struct {
	Exact  string `yaml:"exact,omitempty"`
	Prefix string `yaml:"prefix,omitempty"`
	Regex  string `yaml:"regex,omitempty"`
}

// PathRewrite optionally replaces a path, prefix, or regex match.
type PathRewrite struct {
	Path   string        `yaml:"path,omitempty"`
	Prefix string        `yaml:"prefix,omitempty"`
	Regex  *RegexRewrite `yaml:"regex,omitempty"`
}

// RegexRewrite replaces matches in the request path using RE2 capture groups.
type RegexRewrite struct {
	Pattern      string `yaml:"pattern"`
	Substitution string `yaml:"substitution"`
}

// RouteProcessing describes optional per-route request processing.
type RouteProcessing struct {
	RequestHeaders []RequestHeaderMapping `yaml:"request_headers,omitempty"`
}

// RequestHeaderMapping sets an upstream header from a processed attribute.
type RequestHeaderMapping struct {
	Name          string `yaml:"name"`
	FromAttribute string `yaml:"from_attribute"`
}

func validateRouteProcessing(name string, processing *RouteProcessing) error {
	if processing == nil {
		return nil
	}
	if len(processing.RequestHeaders) == 0 {
		return fmt.Errorf("%s.request_headers must contain at least one header mapping", name)
	}
	seen := make(map[string]struct{}, len(processing.RequestHeaders))
	for i, mapping := range processing.RequestHeaders {
		mappingName := fmt.Sprintf("%s.request_headers[%d]", name, i)
		if !validHeaderFieldName(mapping.Name) {
			return fmt.Errorf("%s.name must be a valid HTTP header field name", mappingName)
		}
		lowerName := strings.ToLower(mapping.Name)
		if forbiddenIdentityHeader(lowerName) {
			return fmt.Errorf("%s.name %q is reserved for credentials, routing, connection, or message framing", mappingName, mapping.Name)
		}
		if _, exists := seen[lowerName]; exists {
			return fmt.Errorf("%s.name %q is duplicated", mappingName, mapping.Name)
		}
		seen[lowerName] = struct{}{}
		if !attributeNamePattern.MatchString(mapping.FromAttribute) {
			return fmt.Errorf("%s.from_attribute must be a valid attribute name", mappingName)
		}
	}
	return nil
}

func validHeaderFieldName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		ch := name[i]
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') {
			continue
		}
		switch ch {
		case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
			continue
		default:
			return false
		}
	}
	return true
}

func forbiddenIdentityHeader(name string) bool {
	if isRequestControlHeader(name) {
		return true
	}
	switch name {
	case authorizationHeaderName, "proxy-authorization", "cookie", "host", "connection", "keep-alive", "proxy-connection",
		"transfer-encoding", "content-length", "trailer", "te", "upgrade", "forwarded", "x-forwarded-for",
		"x-forwarded-host", "x-forwarded-proto", "x-forwarded-port", "x-envoy-original-path", "x-envoy-original-host",
		"x-envoy-upstream-cluster", "x-envoy-decorator-operation":
		return true
	default:
		return strings.HasPrefix(name, "proxy-") || strings.HasPrefix(name, "x-auth-gateway-")
	}
}

func validateAPIRoute(name string, route Route, routes map[string]struct{}) error {
	if err := validateRouteTimeouts(name+".timeouts", route.Timeouts); err != nil {
		return err
	}
	if err := validateRouteProcessing(name+".processing", route.Processing); err != nil {
		return err
	}
	if err := validatePathMatch(name+".path", route.Path); err != nil {
		return err
	}
	if err := validatePathRewrite(name+".rewrite", route.Rewrite); err != nil {
		return err
	}
	if len(route.Methods) == 0 {
		return fmt.Errorf("%s.methods must contain at least one supported HTTP method", name)
	}
	seenMethods := make(map[string]struct{}, len(route.Methods))
	for _, method := range route.Methods {
		if !validMethod(method) {
			return fmt.Errorf("%s.methods must contain supported HTTP methods", name)
		}
		if _, exists := seenMethods[method]; exists {
			return fmt.Errorf("%s.methods contains duplicate method %q", name, method)
		}
		seenMethods[method] = struct{}{}
		if err := addRouteKey(routes, route.Path, method); err != nil {
			return err
		}
	}
	return nil
}

func addRouteKey(routes map[string]struct{}, path PathMatch, method string) error {
	key := pathMatchKey(path) + "\x00" + method
	if _, exists := routes[key]; exists {
		return fmt.Errorf("duplicate API route for method %s and path matcher %q", method, pathMatchValue(path))
	}
	routes[key] = struct{}{}
	return nil
}

func pathMatchKey(path PathMatch) string {
	switch {
	case path.Exact != "":
		return "exact\x00" + path.Exact
	case path.Prefix != "":
		return "prefix\x00" + path.Prefix
	default:
		return "regex\x00" + path.Regex
	}
}

func pathMatchValue(path PathMatch) string {
	switch {
	case path.Exact != "":
		return path.Exact
	case path.Prefix != "":
		return path.Prefix
	default:
		return path.Regex
	}
}

func validatePathMatch(name string, path PathMatch) error {
	count := 0
	if path.Exact != "" {
		count++
		if err := validatePath(name+".exact", path.Exact); err != nil {
			return err
		}
	}
	if path.Prefix != "" {
		count++
		if err := validatePathPrefix(name+".prefix", path.Prefix); err != nil {
			return err
		}
	}
	if path.Regex != "" {
		count++
		if _, err := regexp.Compile(path.Regex); err != nil {
			return fmt.Errorf("%s.regex must be a valid RE2 expression: %w", name, err)
		}
	}
	if count != 1 {
		return fmt.Errorf("%s must set exactly one of exact, prefix, or regex", name)
	}
	return nil
}

func validatePathRewrite(name string, rewrite *PathRewrite) error {
	if rewrite == nil {
		return nil
	}

	count := 0
	if rewrite.Path != "" {
		count++
		if err := validatePath(name+".path", rewrite.Path); err != nil {
			return err
		}
	}
	if rewrite.Prefix != "" {
		count++
		if err := validatePathPrefix(name+".prefix", rewrite.Prefix); err != nil {
			return err
		}
	}
	if rewrite.Regex != nil {
		count++
		if rewrite.Regex.Pattern == "" {
			return fmt.Errorf("%s.regex.pattern must not be empty", name)
		}
		if _, err := regexp.Compile(rewrite.Regex.Pattern); err != nil {
			return fmt.Errorf("%s.regex.pattern must be a valid RE2 expression: %w", name, err)
		}
		if strings.ContainsAny(rewrite.Regex.Substitution, "?#\r\n") {
			return fmt.Errorf("%s.regex.substitution must not contain a query, fragment, or newline", name)
		}
	}
	if count != 1 {
		return fmt.Errorf("%s must set exactly one of path, prefix, or regex", name)
	}
	return nil
}

func validMethod(method string) bool {
	switch method {
	case http.MethodConnect,
		http.MethodDelete,
		http.MethodGet,
		http.MethodHead,
		http.MethodOptions,
		http.MethodPatch,
		http.MethodPost,
		http.MethodPut,
		http.MethodTrace:
		return true
	default:
		return false
	}
}

func validatePath(name, value string) error {
	if value == "" || !strings.HasPrefix(value, "/") || strings.HasPrefix(value, "//") ||
		strings.ContainsAny(value, "?#\\\r\n") || path.Clean(value) != value {
		return fmt.Errorf("%s must be a clean absolute path without a query or fragment", name)
	}
	parsed, err := url.ParseRequestURI(value)
	if err != nil || parsed.IsAbs() {
		return fmt.Errorf("%s must be a valid request path", name)
	}
	return nil
}

func validatePathPrefix(name, value string) error {
	if value == "" {
		return fmt.Errorf("%s must not be empty", name)
	}
	if strings.HasPrefix(value, "//") {
		return fmt.Errorf("%s must be an absolute path prefix", name)
	}
	cleanable := value
	if value != "/" && strings.HasSuffix(value, "/") {
		cleanable = strings.TrimSuffix(value, "/")
	}
	return validatePath(name, cleanable)
}

func isRequestControlHeader(name string) bool { return slices.Contains(requestControlHeaders, name) }

func hasRequestHeaderProcessing(apis []API) bool {
	for _, api := range apis {
		for _, apiRoute := range api.Routes {
			if apiRoute.Processing != nil && len(apiRoute.Processing.RequestHeaders) > 0 {
				return true
			}
		}
	}
	return false
}

func (r Route) clone() Route {
	r.Methods = slices.Clone(r.Methods)
	r.Rewrite = cloneConfigPointer(r.Rewrite)
	r.Processing = cloneConfigPointer(r.Processing)
	r.Timeouts = cloneConfigPointer(r.Timeouts)
	return r
}

func (r PathRewrite) clone() PathRewrite {
	r.Regex = cloneConfigPointer(r.Regex)
	return r
}

func (r RegexRewrite) clone() RegexRewrite {
	return r
}

func (p RouteProcessing) clone() RouteProcessing {
	p.RequestHeaders = slices.Clone(p.RequestHeaders)
	return p
}

func (path PathMatch) toRouteMatch() *route.RouteMatch {
	switch {
	case path.Exact != "":
		return &route.RouteMatch{PathSpecifier: &route.RouteMatch_Path{Path: path.Exact}}
	case path.Prefix != "":
		return &route.RouteMatch{PathSpecifier: &route.RouteMatch_Prefix{Prefix: path.Prefix}}
	default:
		return &route.RouteMatch{PathSpecifier: &route.RouteMatch_SafeRegex{SafeRegex: envoySafeRegex(path.Regex)}}
	}
}
