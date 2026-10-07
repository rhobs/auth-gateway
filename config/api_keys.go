package config

import (
	"fmt"
	"io"
	"maps"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"

	xdscore "github.com/cncf/xds/go/xds/core/v3"
	xdsmatcher "github.com/cncf/xds/go/xds/type/matcher/v3"
	mutationrules "github.com/envoyproxy/go-control-plane/envoy/config/common/mutation_rules/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	rbac "github.com/envoyproxy/go-control-plane/envoy/config/rbac/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	matching "github.com/envoyproxy/go-control-plane/envoy/extensions/common/matching/v3"
	skip "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/common/matcher/action/v3"
	apikey "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/api_key_auth/v3"
	headermutation "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/header_mutation/v3"
	headertometadata "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/header_to_metadata/v3"
	setfilterstate "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/set_filter_state/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	matcher "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	"go.yaml.in/yaml/v3"
	expr "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/anypb"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
)

const (
	apiKeyFilterName         = "envoy.filters.http.api_key_auth"
	apiKeySecretFilename     = "api-keys.yaml"
	apiKeyClientHeader       = "x-auth-gateway-api-key-client"
	apiKeyMetadataNamespace  = "auth_gateway.api_key"
	apiKeyMetadataKey        = "identity"
	apiKeyAttributeKey       = "attribute."
	apiKeyClientNoAttributes = "api-key"
)

// APIKeyCredential binds an opaque key to verified string attributes.
type APIKeyCredential struct {
	Key        string            `yaml:"key"`
	Attributes map[string]string `yaml:"attributes,omitempty"`
}

// LoadAPIKeyCredentials reads one credentials YAML document.
func LoadAPIKeyCredentials(r io.Reader) ([]APIKeyCredential, error) {
	decoder := yaml.NewDecoder(r)
	decoder.KnownFields(true)
	var input struct {
		Credentials *[]APIKeyCredential `yaml:"credentials"`
	}
	if err := decoder.Decode(&input); err != nil {
		return nil, err
	}
	if input.Credentials == nil {
		return nil, fmt.Errorf("credentials document must set credentials (use [] to revoke all keys)")
	}
	var extra any
	if err := decoder.Decode(&extra); err == nil {
		return nil, fmt.Errorf("credentials document must contain exactly one YAML document")
	} else if err != io.EOF {
		return nil, err
	}
	return *input.Credentials, nil
}

// APIKeySecret builds the complete ECDS resource in one Kubernetes Secret.
// An empty credential list revokes all keys. The Secret is not part of GenerateKubernetes.
func APIKeySecret(namespace string, authenticator Authenticator, credentials []APIKeyCredential) (*corev1.Secret, error) {
	if len(validation.IsDNS1123Label(namespace)) != 0 {
		return nil, fmt.Errorf("namespace must be a Kubernetes DNS label")
	}
	data, err := generateAPIKeyECDS(authenticator, credentials, true)
	if err != nil {
		return nil, err
	}
	return &corev1.Secret{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"},
		ObjectMeta: metav1.ObjectMeta{Name: authenticator.APIKey.Secret, Namespace: namespace},
		Type:       corev1.SecretTypeOpaque,
		Data:       map[string][]byte{apiKeySecretFilename: data},
	}, nil
}

// GenerateAPIKeyECDS builds the file Envoy watches for API-key updates.
// An empty credential list revokes all keys.
func GenerateAPIKeyECDS(authenticator Authenticator, credentials []APIKeyCredential) ([]byte, error) {
	return generateAPIKeyECDS(authenticator, credentials, false)
}

func generateAPIKeyECDS(authenticator Authenticator, credentials []APIKeyCredential, requireSecret bool) ([]byte, error) {
	if !apiNamePattern.MatchString(authenticator.Name) || authenticator.JWT != nil || authenticator.APIKey == nil {
		return nil, fmt.Errorf("authenticator must be a named API-key authenticator")
	}
	apiKey := authenticator.APIKey.withDefaults()
	if err := validateAPIKeyAuthenticator("authenticator.api_key", apiKey, requireSecret); err != nil {
		return nil, err
	}
	allowedAttributes := make(map[string]struct{}, len(apiKey.Attributes))
	for _, attribute := range apiKey.Attributes {
		allowedAttributes[attribute] = struct{}{}
	}
	attributeNames := slices.Clone(apiKey.Attributes)
	slices.Sort(attributeNames)
	seenKeys := make(map[string]struct{}, len(credentials))
	entries := make([]*apikey.Credential, 0, len(credentials))
	for index, credential := range credentials {
		if !validCredentialText(credential.Key) {
			return nil, fmt.Errorf("credentials[%d].key must be a nonempty HTTP header value without controls", index)
		}
		if _, exists := seenKeys[credential.Key]; exists {
			return nil, fmt.Errorf("credentials[%d].key is duplicated", index)
		}
		seenKeys[credential.Key] = struct{}{}
		for name, value := range credential.Attributes {
			if _, exists := allowedAttributes[name]; !exists {
				return nil, fmt.Errorf("credentials[%d].attributes contains undeclared attribute %q", index, name)
			}
			if !validCredentialText(value) || strings.Contains(value, ";") {
				return nil, fmt.Errorf("credentials[%d].attributes.%s must be a nonempty HTTP header value without controls or semicolons", index, name)
			}
		}
		entries = append(entries, &apikey.Credential{Key: credential.Key, Client: apiKeyClientValue(attributeNames, credential.Attributes)})
	}
	slices.SortFunc(entries, func(a, b *apikey.Credential) int { return strings.Compare(a.Key, b.Key) })
	native, err := packEnvoy(&apikey.ApiKeyAuth{
		Credentials: entries,
		KeySources:  []*apikey.KeySource{{Header: strings.ToLower(apiKey.Header)}},
		Forwarding:  &apikey.Forwarding{Header: apiKeyClientHeader, HideCredentials: true},
	})
	if err != nil {
		return nil, fmt.Errorf("encode API-key filter: %w", err)
	}
	wrapped, err := packEnvoy(&matching.ExtensionWithMatcher{ExtensionConfig: &core.TypedExtensionConfig{Name: apiKeyFilterName, TypedConfig: native}})
	if err != nil {
		return nil, fmt.Errorf("encode API-key matcher: %w", err)
	}
	resource, err := packEnvoy(&core.TypedExtensionConfig{Name: apiKeyFilterName, TypedConfig: wrapped})
	if err != nil {
		return nil, fmt.Errorf("encode API-key ECDS resource: %w", err)
	}
	jsonData, err := (protojson.MarshalOptions{UseProtoNames: true, EmitDefaultValues: true}).Marshal(resource)
	if err != nil {
		return nil, fmt.Errorf("encode API-key ECDS response: %w", err)
	}
	var document any
	if err := yaml.Unmarshal(jsonData, &document); err != nil {
		return nil, fmt.Errorf("convert API-key ECDS response: %w", err)
	}
	data, err := yaml.Marshal(map[string]any{envoyResourcesFieldName: []any{document}})
	if err != nil {
		return nil, fmt.Errorf("encode API-key ECDS data: %w", err)
	}
	return data, nil
}

func apiKeyClientValue(attributeNames []string, values map[string]string) string {
	if len(attributeNames) == 0 {
		return apiKeyClientNoAttributes
	}
	var client strings.Builder
	for index, name := range attributeNames {
		if index > 0 {
			client.WriteByte(';')
		}
		client.WriteString(name)
		client.WriteByte('=')
		client.WriteString(values[name])
	}
	return client.String()
}

func apiKeyAttributeMetadataKey(attribute string) string {
	return apiKeyAttributeKey + attribute
}

func validCredentialText(value string) bool {
	if value == "" || strings.TrimSpace(value) != value {
		return false
	}
	for _, ch := range value {
		if ch < 0x20 || ch == 0x7f {
			return false
		}
	}
	return true
}

const (
	headerToMetadataFilterName  = "envoy.filters.http.header_to_metadata"
	authenticationFilterName    = "auth_gateway.authentication"
	credentialCleanupFilterName = "auth_gateway.credentials"
	jwtVerifiedHeaderPrefix     = "x-auth-gateway-jwt-verified-"
)

func selectedAuthenticatorNames(server Server) []string {
	if server.Authentication == nil {
		return nil
	}
	if server.Authentication.AnyOf != nil {
		return server.Authentication.AnyOf
	}
	return server.Authentication.AllOf
}

func serverUsesAPIKey(c Config, server Server) bool {
	for _, name := range selectedAuthenticatorNames(server) {
		if findAuthenticator(c, name).APIKey != nil {
			return true
		}
	}
	return false
}

func serverUsesJWT(c Config, server Server) bool {
	for _, name := range selectedAuthenticatorNames(server) {
		if findAuthenticator(c, name).JWT != nil {
			return true
		}
	}
	return false
}

func serverSelectsAuthenticator(server Server, name string) bool {
	return slices.Contains(selectedAuthenticatorNames(server), name)
}

func mixedAnyOf(c Config, server Server) bool {
	return server.Authentication != nil && server.Authentication.AnyOf != nil && serverUsesJWT(c, server) && serverUsesAPIKey(c, server)
}

func jwtVerifiedHeaderName(name string) string { return jwtVerifiedHeaderPrefix + name }

func apiKeyFilter() *hcm.HttpFilter {
	return &hcm.HttpFilter{
		Name: apiKeyFilterName, Disabled: true,
		ConfigType: &hcm.HttpFilter_ConfigDiscovery{ConfigDiscovery: &core.ExtensionConfigSource{
			ConfigSource: fileConfigSource(path.Join(apiKeyDirectory, apiKeySecretFilename)),
			TypeUrls:     []string{string((&matching.ExtensionWithMatcher{}).ProtoReflect().Descriptor().FullName())},
		}},
	}
}

func apiKeyPerRouteConfig(c Config, server Server) (*anypb.Any, error) {
	config := &matching.ExtensionWithMatcherPerRoute{}
	if mixedAnyOf(c, server) {
		matcher, err := apiKeySkipMatcher(c, server)
		if err != nil {
			return nil, err
		}
		config.XdsMatcher = matcher
	}
	perRoute, err := packEnvoy(config)
	if err != nil {
		return nil, err
	}
	return packEnvoy(&route.FilterConfig{Config: perRoute})
}

func apiKeySkipMatcher(c Config, server Server) (*xdsmatcher.Matcher, error) {
	packedSkip, err := packEnvoy(&skip.SkipFilter{})
	if err != nil {
		return nil, fmt.Errorf("encode API-key skip action: %w", err)
	}
	action := &xdsmatcher.Matcher_OnMatch{OnMatch: &xdsmatcher.Matcher_OnMatch_Action{Action: &xdscore.TypedExtensionConfig{Name: "skip", TypedConfig: packedSkip}}}
	var fields []*xdsmatcher.Matcher_MatcherList_FieldMatcher
	for _, name := range selectedAuthenticatorNames(server) {
		authenticator := findAuthenticator(c, name)
		if authenticator.JWT == nil {
			continue
		}
		input, err := packEnvoy(&matcher.HttpRequestHeaderMatchInput{HeaderName: jwtVerifiedHeaderName(name)})
		if err != nil {
			return nil, fmt.Errorf("encode JWT marker input: %w", err)
		}
		fields = append(fields, &xdsmatcher.Matcher_MatcherList_FieldMatcher{
			Predicate: &xdsmatcher.Matcher_MatcherList_Predicate{MatchType: &xdsmatcher.Matcher_MatcherList_Predicate_SinglePredicate_{SinglePredicate: &xdsmatcher.Matcher_MatcherList_Predicate_SinglePredicate{
				Input:   &xdscore.TypedExtensionConfig{Name: "envoy.matching.inputs.request_headers", TypedConfig: input},
				Matcher: &xdsmatcher.Matcher_MatcherList_Predicate_SinglePredicate_ValueMatch{ValueMatch: &xdsmatcher.StringMatcher{MatchPattern: &xdsmatcher.StringMatcher_Exact{Exact: authenticator.JWT.Issuer}}},
			}}},
			OnMatch: action,
		})
	}
	return &xdsmatcher.Matcher{MatcherType: &xdsmatcher.Matcher_MatcherList_{MatcherList: &xdsmatcher.Matcher_MatcherList{Matchers: fields}}}, nil
}

func apiKeyMetadataFilter(authenticator Authenticator) (*hcm.HttpFilter, error) {
	attributeNames := slices.Clone(authenticator.APIKey.Attributes)
	slices.Sort(attributeNames)
	rules := []*headertometadata.Config_Rule{{
		Header: apiKeyClientHeader, Remove: len(attributeNames) == 0,
		OnHeaderPresent: &headertometadata.Config_KeyValuePair{
			MetadataNamespace: apiKeyMetadataNamespace, Key: apiKeyMetadataKey,
		},
	}}
	for index, attribute := range attributeNames {
		rules = append(rules, &headertometadata.Config_Rule{
			Header: apiKeyClientHeader, Remove: index == len(attributeNames)-1,
			OnHeaderPresent: &headertometadata.Config_KeyValuePair{
				MetadataNamespace: apiKeyMetadataNamespace,
				Key:               apiKeyAttributeMetadataKey(attribute),
				RegexValueRewrite: &matcher.RegexMatchAndSubstitute{
					Pattern:      apiKeyRegexMatcher(apiKeyClientPattern(authenticator.APIKey.Attributes, attribute)),
					Substitution: `\1`,
				},
			},
		})
	}
	config, err := packEnvoy(&headertometadata.Config{RequestRules: rules})
	if err != nil {
		return nil, err
	}
	return &hcm.HttpFilter{Name: headerToMetadataFilterName, ConfigType: &hcm.HttpFilter_TypedConfig{TypedConfig: config}}, nil
}

func apiKeyClientPattern(attributes []string, capturedAttribute string) string {
	attributeNames := slices.Clone(attributes)
	slices.Sort(attributeNames)
	if len(attributeNames) == 0 {
		return "^" + regexp.QuoteMeta(apiKeyClientNoAttributes) + "$"
	}
	var pattern strings.Builder
	pattern.WriteByte('^')
	for index, attribute := range attributeNames {
		if index > 0 {
			pattern.WriteByte(';')
		}
		pattern.WriteString(regexp.QuoteMeta(attribute))
		pattern.WriteByte('=')
		if attribute == capturedAttribute {
			pattern.WriteString("([^;]*)")
		} else {
			pattern.WriteString("[^;]*")
		}
	}
	pattern.WriteByte('$')
	return pattern.String()
}

func apiKeyRegexMatcher(pattern string) *matcher.RegexMatcher {
	return &matcher.RegexMatcher{
		EngineType: &matcher.RegexMatcher_GoogleRe2{GoogleRe2: &matcher.RegexMatcher_GoogleRE2{}}, //nolint:staticcheck // The pinned Envoy API exposes this RE2 field.
		Regex:      pattern,
	}
}

func apiKeyIdentityPrincipal(authenticator Authenticator) *rbac.Principal {
	return apiKeyMetadataPrincipal([]string{apiKeyMetadataKey}, &matcher.ValueMatcher{MatchPattern: &matcher.ValueMatcher_StringMatch{StringMatch: &matcher.StringMatcher{MatchPattern: &matcher.StringMatcher_SafeRegex{SafeRegex: apiKeyRegexMatcher(apiKeyClientPattern(authenticator.APIKey.Attributes, ""))}}}})
}

func apiKeyMetadataPrincipal(keys []string, value *matcher.ValueMatcher) *rbac.Principal {
	segments := make([]*matcher.MetadataMatcher_PathSegment, 0, len(keys))
	for _, key := range keys {
		segments = append(segments, metadataPathSegment(key))
	}
	return &rbac.Principal{Identifier: &rbac.Principal_SourcedMetadata{SourcedMetadata: &rbac.SourcedMetadata{
		MetadataSource:  rbac.MetadataSource_DYNAMIC,
		MetadataMatcher: &matcher.MetadataMatcher{Filter: apiKeyMetadataNamespace, Path: segments, Value: value},
	}}}
}

func jwtMarkerPrincipal(authenticator Authenticator) *rbac.Principal {
	return &rbac.Principal{Identifier: &rbac.Principal_Header{Header: &route.HeaderMatcher{
		Name:                 jwtVerifiedHeaderName(authenticator.Name),
		HeaderMatchSpecifier: &route.HeaderMatcher_StringMatch{StringMatch: &matcher.StringMatcher{MatchPattern: &matcher.StringMatcher_Exact{Exact: authenticator.JWT.Issuer}}},
	}}}
}

func grantPrincipalForServer(c Config, server Server, grant AuthorizationGrant) *rbac.Principal {
	principal := grantPrincipal(c, grant)
	if mixedAnyOf(c, server) {
		if authenticator := findAuthenticator(c, grant.Authenticator); authenticator.JWT != nil {
			return andPrincipals(principal, jwtMarkerPrincipal(authenticator))
		}
	}
	return principal
}

func andPrincipals(values ...*rbac.Principal) *rbac.Principal {
	if len(values) == 1 {
		return values[0]
	}
	return &rbac.Principal{Identifier: &rbac.Principal_AndIds{AndIds: &rbac.Principal_Set{Ids: values}}}
}

func serverAuthenticationRBACRules(c Config, server Server) *rbac.RBAC {
	var keyAuthenticator Authenticator
	for _, name := range selectedAuthenticatorNames(server) {
		if selected := findAuthenticator(c, name); selected.APIKey != nil {
			keyAuthenticator = selected
			break
		}
	}
	principal := apiKeyIdentityPrincipal(keyAuthenticator)
	policy := &rbac.Policy{Permissions: []*rbac.Permission{{Rule: &rbac.Permission_Any{Any: true}}}}
	if mixedAnyOf(c, server) {
		alternatives := []*rbac.Principal{principal}
		for _, name := range selectedAuthenticatorNames(server) {
			if authenticator := findAuthenticator(c, name); authenticator.JWT != nil {
				alternatives = append(alternatives, jwtMarkerPrincipal(authenticator))
			}
		}
		principal = &rbac.Principal{Identifier: &rbac.Principal_OrIds{OrIds: &rbac.Principal_Set{Ids: alternatives}}}
	} else if server.Authentication.AllOf != nil && serverUsesJWT(c, server) {
		var jwtAuthenticator Authenticator
		for _, name := range selectedAuthenticatorNames(server) {
			if selected := findAuthenticator(c, name); selected.JWT != nil {
				jwtAuthenticator = selected
				break
			}
		}
		principals := []*rbac.Principal{principal}
		builder := &celExpressionBuilder{}
		var equality []*expr.Expr
		for _, attribute := range keyAuthenticator.APIKey.Attributes {
			jwtAttribute, shared := jwtAuthenticator.JWT.Attributes[attribute]
			if !shared {
				continue
			}
			valueMatcher := nonemptyScalarValueMatcher()
			principals = append(principals,
				jwtClaimPrincipal(append([]string{jwtAuthenticator.Name}, jwtAttribute.ClaimPath...), valueMatcher),
				apiKeyMetadataPrincipal([]string{apiKeyAttributeMetadataKey(attribute)}, valueMatcher))
			equality = append(equality, builder.call("_==_",
				builder.metadataValue(jwtAuthnFilterName, append([]string{jwtAuthenticator.Name}, jwtAttribute.ClaimPath...)),
				builder.metadataValue(apiKeyMetadataNamespace, []string{apiKeyAttributeMetadataKey(attribute)})))
		}
		principal = andPrincipals(principals...)
		if len(equality) > 0 {
			condition := equality[0]
			for _, next := range equality[1:] {
				condition = builder.call("_&&_", condition, next)
			}
			policy.Condition = condition
		}
	}
	policy.Principals = []*rbac.Principal{principal}
	return &rbac.RBAC{Action: rbac.RBAC_ALLOW, Policies: map[string]*rbac.Policy{"authenticated": policy}}
}

func nonemptyScalarValueMatcher() *matcher.ValueMatcher {
	return &matcher.ValueMatcher{MatchPattern: &matcher.ValueMatcher_StringMatch{StringMatch: &matcher.StringMatcher{MatchPattern: &matcher.StringMatcher_SafeRegex{SafeRegex: &matcher.RegexMatcher{
		EngineType: &matcher.RegexMatcher_GoogleRe2{GoogleRe2: &matcher.RegexMatcher_GoogleRE2{}}, //nolint:staticcheck // The pinned Envoy API exposes this RE2 field.
		Regex:      headerValuePattern,
	}}}}}
}

func keyGrantPrincipal(authenticator Authenticator, grant AuthorizationGrant) *rbac.Principal {
	conditions := []*rbac.Principal{apiKeyIdentityPrincipal(authenticator)}
	for _, attribute := range slices.Sorted(maps.Keys(grant.Attributes)) {
		allowed := grant.Attributes[attribute]
		values := make([]*matcher.ValueMatcher, 0, len(allowed))
		for _, value := range allowed {
			values = append(values, &matcher.ValueMatcher{MatchPattern: &matcher.ValueMatcher_StringMatch{StringMatch: &matcher.StringMatcher{MatchPattern: &matcher.StringMatcher_Exact{Exact: value}}}})
		}
		valueMatcher := values[0]
		if len(values) > 1 {
			valueMatcher = &matcher.ValueMatcher{MatchPattern: &matcher.ValueMatcher_OrMatch{OrMatch: &matcher.OrMatcher{ValueMatchers: values}}}
		}
		conditions = append(conditions, apiKeyMetadataPrincipal([]string{apiKeyAttributeMetadataKey(attribute)}, valueMatcher))
	}
	return andPrincipals(conditions...)
}

func serverAttributeInitializationConfig(c Config, server Server) *setfilterstate.Config {
	config := &setfilterstate.Config{}
	for _, name := range selectedAuthenticatorNames(server) {
		authenticator := findAuthenticator(c, name)
		if authenticator.JWT != nil {
			for _, attribute := range slices.Sorted(maps.Keys(authenticator.JWT.Attributes)) {
				claimPath := append([]string{name}, authenticator.JWT.Attributes[attribute].ClaimPath...)
				config.OnRequestHeaders = append(config.OnRequestHeaders, filterStateValue(filterStateKey(attribute), jwtClaimExpression(claimPath)))
			}
		} else {
			attributes := slices.Clone(authenticator.APIKey.Attributes)
			slices.Sort(attributes)
			for _, attribute := range attributes {
				config.OnRequestHeaders = append(config.OnRequestHeaders, filterStateValue(filterStateKey(attribute), apiKeyAttributeExpression(attribute)))
			}
		}
	}
	return config
}

func apiKeyAttributeExpression(attribute string) string {
	namespace := `metadata.filter_metadata["` + apiKeyMetadataNamespace + `"]`
	key := celStringLiteral(apiKeyAttributeMetadataKey(attribute))
	current := namespace + "[" + key + "]"
	return "((\"" + apiKeyMetadataNamespace + "\" in metadata.filter_metadata" + celAndSeparator + key + " in " + namespace + ") && type(" + current + ") == string && " + current + " != \"\") ? " + current + " : \"\""
}

func credentialCleanupConfig(c Config) *headermutation.HeaderMutation {
	removed := map[string]struct{}{authorizationHeaderName: {}, apiKeyClientHeader: {}}
	if authenticator, exists := c.apiKeyAuthenticator(); exists {
		removed[strings.ToLower(authenticator.APIKey.Header)] = struct{}{}
	}
	for _, authenticator := range c.Authenticators {
		if authenticator.JWT != nil {
			removed[jwtVerifiedHeaderName(authenticator.Name)] = struct{}{}
		}
	}
	mutations := make([]*mutationrules.HeaderMutation, 0, len(removed))
	for _, name := range slices.Sorted(maps.Keys(removed)) {
		mutations = append(mutations, &mutationrules.HeaderMutation{Action: &mutationrules.HeaderMutation_Remove{Remove: name}})
	}
	return &headermutation.HeaderMutation{Mutations: &headermutation.Mutations{RequestMutations: mutations}}
}

func credentialCleanupFilter(c Config) (*hcm.HttpFilter, error) {
	cleanup, err := packEnvoy(credentialCleanupConfig(c))
	if err != nil {
		return nil, fmt.Errorf("encode credential cleanup filter: %w", err)
	}
	return &hcm.HttpFilter{Name: credentialCleanupFilterName, ConfigType: &hcm.HttpFilter_TypedConfig{TypedConfig: cleanup}}, nil
}

func attributeInitializationFilterName(index int) string {
	return "auth_gateway.attributes.server-" + strconv.Itoa(index)
}

type celExpressionBuilder struct{ next int64 }

func (b *celExpressionBuilder) id() int64 {
	b.next++
	return b.next
}

func (b *celExpressionBuilder) call(name string, args ...*expr.Expr) *expr.Expr {
	return &expr.Expr{Id: b.id(), ExprKind: &expr.Expr_CallExpr{CallExpr: &expr.Expr_Call{Function: name, Args: args}}}
}

func (b *celExpressionBuilder) metadataValue(namespace string, keys []string) *expr.Expr {
	value := &expr.Expr{Id: b.id(), ExprKind: &expr.Expr_IdentExpr{IdentExpr: &expr.Expr_Ident{Name: "metadata"}}}
	value = &expr.Expr{Id: b.id(), ExprKind: &expr.Expr_SelectExpr{SelectExpr: &expr.Expr_Select{Operand: value, Field: "filter_metadata"}}}
	for _, key := range append([]string{namespace}, keys...) {
		literal := &expr.Expr{Id: b.id(), ExprKind: &expr.Expr_ConstExpr{ConstExpr: &expr.Constant{ConstantKind: &expr.Constant_StringValue{StringValue: key}}}}
		value = b.call("_[_]", value, literal)
	}
	return value
}
