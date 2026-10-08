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
	authenticator.APIKey = &apiKey
	if err := validateAuthenticatorAttributes("authenticator", authenticator, apiKey.Header); err != nil {
		return nil, err
	}
	attributeNames := authenticator.credentialAttributeNames()
	allowedAttributes := make(map[string]struct{}, len(attributeNames))
	for _, attribute := range attributeNames {
		allowedAttributes[attribute] = struct{}{}
	}
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
	headerToMetadataFilterName     = "envoy.filters.http.header_to_metadata"
	requestHeaderMetadataNamespace = "auth_gateway.request_headers"
	authenticationFilterName       = "auth_gateway.authentication"
	credentialCleanupFilterName    = "auth_gateway.credentials"
	jwtVerifiedHeaderPrefix        = "x-auth-gateway-jwt-verified-"
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

func (c Config) toAPIKeyPerRouteConfig(server Server) (*anypb.Any, error) {
	config := &matching.ExtensionWithMatcherPerRoute{}
	if mixedAnyOf(c, server) {
		matcher, err := c.toAPIKeySkipMatcher(server)
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

func (c Config) toAPIKeySkipMatcher(server Server) (*xdsmatcher.Matcher, error) {
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

func requestHeaderSources(c Config, serverIndexes []int) []string {
	headers := make(map[string]struct{})
	for _, index := range serverIndexes {
		for _, name := range selectedAuthenticatorNames(c.Servers[index]) {
			for _, source := range findAuthenticator(c, name).Attributes {
				if source.Header != nil {
					headers[strings.ToLower(*source.Header)] = struct{}{}
				}
			}
		}
	}
	return slices.Sorted(maps.Keys(headers))
}

func (authenticator Authenticator) toRequestMetadataFilter(headers []string) (*hcm.HttpFilter, error) {
	var rules []*headertometadata.Config_Rule
	if authenticator.APIKey != nil {
		attributeNames := authenticator.credentialAttributeNames()
		rules = append(rules, &headertometadata.Config_Rule{
			Header: apiKeyClientHeader, Remove: len(attributeNames) == 0,
			OnHeaderPresent: &headertometadata.Config_KeyValuePair{
				MetadataNamespace: apiKeyMetadataNamespace, Key: apiKeyMetadataKey,
			},
		})
		for index, attribute := range attributeNames {
			rules = append(rules, &headertometadata.Config_Rule{
				Header: apiKeyClientHeader, Remove: index == len(attributeNames)-1,
				OnHeaderPresent: &headertometadata.Config_KeyValuePair{
					MetadataNamespace: apiKeyMetadataNamespace,
					Key:               apiKeyAttributeMetadataKey(attribute),
					RegexValueRewrite: &matcher.RegexMatchAndSubstitute{
						Pattern:      apiKeyRegexMatcher(apiKeyClientPattern(attributeNames, attribute)),
						Substitution: `\1`,
					},
				},
			})
		}
	}
	for _, header := range headers {
		rules = append(rules, &headertometadata.Config_Rule{
			Header: header,
			OnHeaderPresent: &headertometadata.Config_KeyValuePair{
				MetadataNamespace: requestHeaderMetadataNamespace,
				Key:               header,
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
		Regex: pattern,
	}
}

func (authenticator Authenticator) toAPIKeyIdentityPrincipal() *rbac.Principal {
	return apiKeyMetadataPrincipal([]string{apiKeyMetadataKey}, &matcher.ValueMatcher{MatchPattern: &matcher.ValueMatcher_StringMatch{StringMatch: &matcher.StringMatcher{MatchPattern: &matcher.StringMatcher_SafeRegex{SafeRegex: apiKeyRegexMatcher(apiKeyClientPattern(authenticator.credentialAttributeNames(), ""))}}}})
}

func apiKeyMetadataPrincipal(keys []string, value *matcher.ValueMatcher) *rbac.Principal {
	return dynamicMetadataPrincipal(apiKeyMetadataNamespace, keys, value)
}

func (authenticator Authenticator) toJWTMarkerPrincipal() *rbac.Principal {
	return &rbac.Principal{Identifier: &rbac.Principal_Header{Header: &route.HeaderMatcher{
		Name:                 jwtVerifiedHeaderName(authenticator.Name),
		HeaderMatchSpecifier: &route.HeaderMatcher_StringMatch{StringMatch: &matcher.StringMatcher{MatchPattern: &matcher.StringMatcher_Exact{Exact: authenticator.JWT.Issuer}}},
	}}}
}

func (c Config) toGrantPrincipalForServer(server Server, grant AuthorizationGrant) *rbac.Principal {
	principal := c.toGrantPrincipal(grant)
	if mixedAnyOf(c, server) {
		if authenticator := findAuthenticator(c, grant.Authenticator); authenticator.JWT != nil {
			return andPrincipals(principal, authenticator.toJWTMarkerPrincipal())
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

func (c Config) toServerAuthenticationRBACRules(server Server) *rbac.RBAC {
	var keyAuthenticator Authenticator
	for _, name := range selectedAuthenticatorNames(server) {
		if selected := findAuthenticator(c, name); selected.APIKey != nil {
			keyAuthenticator = selected
			break
		}
	}
	principal := keyAuthenticator.toAPIKeyIdentityPrincipal()
	policy := &rbac.Policy{Permissions: []*rbac.Permission{{Rule: &rbac.Permission_Any{Any: true}}}}
	if mixedAnyOf(c, server) {
		alternatives := []*rbac.Principal{principal}
		for _, name := range selectedAuthenticatorNames(server) {
			if authenticator := findAuthenticator(c, name); authenticator.JWT != nil {
				alternatives = append(alternatives, authenticator.toJWTMarkerPrincipal())
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
		for _, attribute := range slices.Sorted(maps.Keys(keyAuthenticator.Attributes)) {
			_, shared := jwtAuthenticator.Attributes[attribute]
			if !shared {
				continue
			}
			jwtNamespace, jwtPath := attributeMetadataPath(jwtAuthenticator, attribute)
			keyNamespace, keyPath := attributeMetadataPath(keyAuthenticator, attribute)
			valueMatcher := nonemptyScalarValueMatcher()
			principals = append(principals,
				dynamicMetadataPrincipal(jwtNamespace, jwtPath, valueMatcher),
				dynamicMetadataPrincipal(keyNamespace, keyPath, valueMatcher))
			equality = append(equality, builder.call("_==_",
				builder.metadataValue(jwtNamespace, jwtPath),
				builder.metadataValue(keyNamespace, keyPath)))
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
		Regex: headerValuePattern,
	}}}}}
}

func (authenticator Authenticator) toKeyGrantPrincipal(grant AuthorizationGrant) *rbac.Principal {
	conditions := []*rbac.Principal{authenticator.toAPIKeyIdentityPrincipal()}
	for _, attribute := range slices.Sorted(maps.Keys(grant.Attributes)) {
		namespace, path := attributeMetadataPath(authenticator, attribute)
		conditions = append(conditions, dynamicMetadataPrincipal(namespace, path, allowedStringValueMatcher(grant.Attributes[attribute])))
	}
	return andPrincipals(conditions...)
}

func (c Config) toServerAttributeInitializationConfig(server Server) *setfilterstate.Config {
	config := &setfilterstate.Config{}
	for _, name := range selectedAuthenticatorNames(server) {
		authenticator := findAuthenticator(c, name)
		for _, attribute := range slices.Sorted(maps.Keys(authenticator.Attributes)) {
			source := authenticator.Attributes[attribute]
			var expression string
			switch {
			case source.Header != nil:
				expression = headerAttributeExpression(authenticator, *source.Header)
			case authenticator.JWT != nil:
				expression = jwtClaimExpression(append([]string{name}, source.ClaimPath...))
			default:
				expression = apiKeyAttributeExpression(attribute)
			}
			config.OnRequestHeaders = append(config.OnRequestHeaders, filterStateValue(filterStateKey(attribute), expression))
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

func (c Config) toCredentialCleanupConfig() *headermutation.HeaderMutation {
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

// toCredentialCleanupFilter builds the Envoy filter that removes gateway credentials and JWT verification markers before requests reach upstreams.
func (c Config) toCredentialCleanupFilter() (*hcm.HttpFilter, error) {
	cleanup, err := packEnvoy(c.toCredentialCleanupConfig())
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
