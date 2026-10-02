package config

import (
	"bytes"
	"encoding/json"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	headermutation "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/header_mutation/v3"
	jwt "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/jwt_authn/v3"
	lua "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/lua/v3"
	httpRBAC "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/rbac/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	"go.yaml.in/yaml/v3"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/anypb"
)

func TestGenerateJWTAuthenticationMatchesEnvoyGolden(t *testing.T) {
	c, err := Load(bytes.NewReader([]byte(readFixture(t, "jwt-auth.yaml"))))
	if err != nil {
		t.Fatal(err)
	}
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	goldenPath := filepath.Join("testdata", "envoy", "jwt-auth.yaml.golden")
	if *updateGolden {
		if err := os.WriteFile(goldenPath, files["envoy.yaml"], 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if want, err := os.ReadFile(goldenPath); err != nil {
		t.Fatal(err)
	} else if !bytes.Equal(files["envoy.yaml"], want) {
		t.Fatal("generated JWT Envoy config does not match the golden file")
	}
	luaGoldenPath := filepath.Join("testdata", "lua", "jwt.lua.golden")
	if *updateGolden {
		if err := os.WriteFile(luaGoldenPath, files["lua/jwt.lua"], 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if want, err := os.ReadFile(luaGoldenPath); err != nil {
		t.Fatal(err)
	} else if !bytes.Equal(files["lua/jwt.lua"], want) {
		t.Fatal("generated JWT Lua script does not match the golden file")
	}
	bootstrapConfig := decodeBootstrap(t, files["envoy.yaml"])
	if len(bootstrapConfig.StaticResources.Clusters) != len(c.APIs)+len(c.Authenticators) {
		t.Fatalf("cluster count = %d", len(bootstrapConfig.StaticResources.Clusters))
	}
	clusters := map[string]*cluster.Cluster{}
	for _, item := range bootstrapConfig.StaticResources.Clusters {
		clusters[item.Name] = item
	}
	for _, name := range []string{"issuer-one", "issuer-two"} {
		jwks := clusters[jwksClusterName(name)]
		if jwks == nil || jwks.TransportSocket == nil {
			t.Fatalf("missing TLS JWKS cluster for %q", name)
		}
		var upstream tls.UpstreamTlsContext
		if err := jwks.TransportSocket.GetTypedConfig().UnmarshalTo(&upstream); err != nil {
			t.Fatal(err)
		}
		if upstream.GetSni() == "" || upstream.GetCommonTlsContext().GetValidationContext().GetTrustedCa().GetFilename() == "" {
			t.Fatalf("JWKS TLS validation is not enabled for %q", name)
		}
	}
	generatedListener := bootstrapConfig.StaticResources.Listeners[0]
	for _, chain := range generatedListener.FilterChains {
		var manager hcm.HttpConnectionManager
		if err := chain.Filters[0].GetTypedConfig().UnmarshalTo(&manager); err != nil {
			t.Fatal(err)
		}
		if len(manager.HttpFilters) != 4 || manager.HttpFilters[0].Name != "envoy.filters.http.jwt_authn" || manager.HttpFilters[1].Name != "envoy.filters.http.lua" || manager.HttpFilters[2].Name != "envoy.filters.http.rbac" || manager.HttpFilters[3].Name != "envoy.filters.http.router" {
			t.Fatalf("HTTP filter order = %v", manager.HttpFilters)
		}
		luaFilter := manager.HttpFilters[1]
		if luaFilter.GetTypedConfig() != nil || luaFilter.GetConfigDiscovery() == nil {
			t.Fatalf("Lua filter config = %#v, want file-based ECDS", luaFilter.GetConfigType())
		}
		ecds := luaFilter.GetConfigDiscovery()
		if len(ecds.GetTypeUrls()) != 1 || ecds.GetTypeUrls()[0] != string((&lua.Lua{}).ProtoReflect().Descriptor().FullName()) {
			t.Fatalf("Lua ECDS type URLs = %v", ecds.GetTypeUrls())
		}
		fileSource := ecds.GetConfigSource().GetPathConfigSource()
		if ecds.GetConfigSource().GetResourceApiVersion() != core.ApiVersion_V3 ||
			fileSource.GetPath() != path.Join(configDirectory, identityMappingECDSRelativePath) ||
			fileSource.GetWatchedDirectory().GetPath() != path.Join(configDirectory, "lua") {
			t.Fatalf("Lua ECDS file source = %#v", fileSource)
		}
		var yamlDocument map[string]any
		if err := yaml.Unmarshal(files[identityMappingECDSRelativePath], &yamlDocument); err != nil {
			t.Fatal(err)
		}
		jsonDocument, err := json.Marshal(yamlDocument)
		if err != nil {
			t.Fatal(err)
		}
		var ecdsDocument map[string]any
		if err := json.Unmarshal(jsonDocument, &ecdsDocument); err != nil {
			t.Fatal(err)
		}
		resources, ok := ecdsDocument["resources"].([]any)
		if !ok || len(resources) != 1 {
			t.Fatalf("Lua ECDS resources = %#v, want one", ecdsDocument["resources"])
		}
		resourceData, err := json.Marshal(resources[0])
		if err != nil {
			t.Fatal(err)
		}
		var resource anypb.Any
		if err := protojson.Unmarshal(resourceData, &resource); err != nil {
			t.Fatal(err)
		}
		var extension core.TypedExtensionConfig
		if err := resource.UnmarshalTo(&extension); err != nil {
			t.Fatal(err)
		}
		if extension.GetName() != "envoy.filters.http.lua" {
			t.Fatalf("Lua ECDS resource name = %q", extension.GetName())
		}
		var luaConfig lua.Lua
		if err := extension.GetTypedConfig().UnmarshalTo(&luaConfig); err != nil {
			t.Fatal(err)
		}
		if source := luaConfig.GetDefaultSourceCode(); source.GetInlineString() != string(files["lua/jwt.lua"]) || source.GetFilename() != "" {
			t.Fatal("Lua ECDS resource does not embed the generated identity script")
		}
		if script := string(files["lua/jwt.lua"]); !strings.Contains(script, "mapped_attributes") || !strings.Contains(script, `metadata:set("auth_gateway_attributes", name, value)`) || !strings.Contains(script, "claim_path") {
			t.Fatal("identity mapping script is missing claim extraction or mapped-attribute metadata")
		} else if strings.Contains(script, "headers:replace") || strings.Contains(script, "headers:remove") {
			t.Fatal("identity mapping script mutates request headers")
		}
		var jwtConfig jwt.JwtAuthentication
		if err := manager.HttpFilters[0].GetTypedConfig().UnmarshalTo(&jwtConfig); err != nil {
			t.Fatal(err)
		}
		if len(jwtConfig.Providers) != 2 || len(jwtConfig.RequirementMap) != 1 {
			t.Fatalf("JWT providers/requirements = %d/%d", len(jwtConfig.Providers), len(jwtConfig.RequirementMap))
		}
		for _, provider := range jwtConfig.Providers {
			if !provider.RequireExpiration || provider.Forward || provider.PayloadInMetadata == "" {
				t.Fatalf("JWT provider requirements = %#v", provider)
			}
		}
		for _, host := range manager.GetRouteConfig().GetVirtualHosts() {
			if host.Name == "public.example.test" {
				if len(host.TypedPerFilterConfig) != 0 {
					t.Fatalf("public virtual host %q has JWT requirements", host.Name)
				}
				continue
			}
			if len(host.TypedPerFilterConfig) != 2 {
				t.Fatalf("virtual host %q lacks a scoped JWT requirement", host.Name)
			}
			var requirement jwt.PerRouteConfig
			if err := host.TypedPerFilterConfig["envoy.filters.http.jwt_authn"].UnmarshalTo(&requirement); err != nil {
				t.Fatal(err)
			}
			if requirement.GetRequirementName() == "" {
				t.Fatalf("virtual host %q JWT requirement is empty", host.Name)
			}
			var rbacConfig httpRBAC.RBACPerRoute
			if err := host.TypedPerFilterConfig["envoy.filters.http.rbac"].UnmarshalTo(&rbacConfig); err != nil {
				t.Fatal(err)
			}
			if rbacConfig.GetRbac().GetRules().GetAction() != 0 {
				t.Fatalf("unexpected RBAC action = %v", rbacConfig.GetRbac().GetRules().GetAction())
			}
		}
	}
}

func TestJWTLuaECDSConfigMap(t *testing.T) {
	config := loadAuthExample(t)
	files, err := Generate(config)
	if err != nil {
		t.Fatal(err)
	}
	resources, err := GenerateKubernetes(config)
	if err != nil {
		t.Fatal(err)
	}
	if resources.LuaConfigMap == nil {
		t.Fatal("JWT deployment has no Lua ConfigMap")
	}
	if _, exists := resources.ConfigMap.Data[identityMappingECDSRelativePath]; exists {
		t.Fatal("bootstrap ConfigMap also contains the Lua ECDS response")
	}
	if got := resources.LuaConfigMap.Name; got != config.Kubernetes.Name+"-lua" {
		t.Fatalf("Lua ConfigMap name = %q", got)
	}
	if got := resources.LuaConfigMap.Data["jwt.yaml"]; got == "" || got != string(files[identityMappingECDSRelativePath]) {
		t.Fatal("Lua ConfigMap does not contain the generated ECDS response")
	}
	if _, exists := resources.LuaConfigMap.Data["jwt.lua"]; exists {
		t.Fatal("Lua ConfigMap should load the ECDS resource with the script embedded")
	}

	var luaVolumeFound, luaMountFound bool
	for _, volume := range resources.Deployment.Spec.Template.Spec.Volumes {
		if volume.Name != "lua-config" {
			continue
		}
		luaVolumeFound = true
		if volume.ConfigMap == nil || volume.ConfigMap.Name != resources.LuaConfigMap.Name || len(volume.ConfigMap.Items) != 1 ||
			volume.ConfigMap.Items[0].Key != "jwt.yaml" || volume.ConfigMap.Items[0].Path != "jwt.yaml" {
			t.Fatalf("Lua volume = %#v", volume)
		}
	}
	for _, mount := range resources.Deployment.Spec.Template.Spec.Containers[0].VolumeMounts {
		if mount.Name == "lua-config" {
			luaMountFound = mount.MountPath == path.Join(configDirectory, "lua") && mount.ReadOnly
		}
	}
	if !luaVolumeFound || !luaMountFound {
		t.Fatalf("separate Lua volume/mount found = %t/%t", luaVolumeFound, luaMountFound)
	}

	if len(resources.Deployment.Spec.Template.Annotations) != 0 {
		t.Fatalf("deployment template annotations = %v, want no generated checksum", resources.Deployment.Spec.Template.Annotations)
	}
	config.Authenticators[0].JWT.Attributes["tenant_id"].Mappings["client-123"] = "team-c"
	updated, err := GenerateKubernetes(config)
	if err != nil {
		t.Fatal(err)
	}
	if resources.LuaConfigMap.Data["jwt.yaml"] == updated.LuaConfigMap.Data["jwt.yaml"] {
		t.Fatal("changing the identity mapping did not update the Lua ECDS ConfigMap")
	}
	if resources.ConfigMap.Data["envoy.yaml"] != updated.ConfigMap.Data["envoy.yaml"] {
		t.Fatal("changing only a Lua mapping unexpectedly changed the Envoy bootstrap")
	}
	if !reflect.DeepEqual(resources.Deployment.Spec.Template, updated.Deployment.Spec.Template) {
		t.Fatal("changing only a Lua mapping unexpectedly changed the Deployment template")
	}
}

func TestGenerateJWTExampleMatchesEnvoyGolden(t *testing.T) {
	c := loadAuthExample(t)
	files, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("testdata", "envoy", "jwt-full.yaml.golden")
	if *updateGolden {
		if err := os.WriteFile(path, files["envoy.yaml"], 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(files["envoy.yaml"], want) {
		t.Fatal("generated full JWT Envoy config does not match the golden file")
	}
}

func TestJWTHeaderMutationRunsAfterAuthorization(t *testing.T) {
	files, err := Generate(loadAuthExample(t))
	if err != nil {
		t.Fatal(err)
	}
	bootstrapConfig := decodeBootstrap(t, files["envoy.yaml"])
	for _, chain := range bootstrapConfig.StaticResources.Listeners[0].FilterChains {
		manager := decodeHTTPManager(t, chain)
		filterNames := make([]string, len(manager.HttpFilters))
		var headerMutationFilter *hcm.HttpFilter
		for i, filter := range manager.HttpFilters {
			filterNames[i] = filter.Name
			if filter.Name == "envoy.filters.http.header_mutation" {
				headerMutationFilter = filter
			}
		}
		if want := []string{"envoy.filters.http.jwt_authn", "envoy.filters.http.lua", "envoy.filters.http.rbac", "envoy.filters.http.header_mutation", "envoy.filters.http.router"}; !equalStrings(filterNames, want) {
			t.Fatalf("HTTP filter order = %v, want %v", filterNames, want)
		}
		if headerMutationFilter == nil {
			t.Fatal("request header mutation filter is missing")
		}
		var filterConfig headermutation.HeaderMutation
		if err := headerMutationFilter.GetTypedConfig().UnmarshalTo(&filterConfig); err != nil {
			t.Fatal(err)
		}
		removed := make(map[string]bool)
		for _, mutation := range filterConfig.GetMutations().GetRequestMutations() {
			removed[mutation.GetRemove()] = mutation.GetRemove() != ""
		}
		if len(removed) != 2 || !removed["x-scope-orgid"] || !removed["x-writer-id"] {
			t.Fatalf("managed request headers removed = %v", removed)
		}

		for _, host := range manager.GetRouteConfig().GetVirtualHosts() {
			assertRouteHeaders := func(routeName string, want map[string]string) {
				t.Helper()
				for _, generatedRoute := range host.GetRoutes() {
					if generatedRoute.GetName() != routeName {
						continue
					}
					packed := generatedRoute.GetTypedPerFilterConfig()["envoy.filters.http.header_mutation"]
					if packed == nil {
						t.Fatalf("route %q lacks header mutation config", routeName)
					}
					var perRoute headermutation.HeaderMutationPerRoute
					if err := packed.UnmarshalTo(&perRoute); err != nil {
						t.Fatal(err)
					}
					got := make(map[string]string)
					for _, mutation := range perRoute.GetMutations().GetRequestMutations() {
						append := mutation.GetAppend()
						if append != nil && append.GetHeader() != nil {
							got[append.GetHeader().GetKey()] = append.GetHeader().GetValue()
						}
					}
					if !equalStringMaps(got, want) {
						t.Fatalf("route %q request header mutations = %v, want %v", routeName, got, want)
					}
					return
				}
				t.Fatalf("route %q not found on virtual host %q", routeName, host.GetName())
			}
			assertRouteHeaders("api-0-metrics-write-route-0-method-0", map[string]string{
				"X-Scope-OrgID": "%DYNAMIC_METADATA(auth_gateway_attributes:tenant_id)%",
				"X-Writer-ID":   "%DYNAMIC_METADATA(auth_gateway_attributes:writer_id)%",
			})
			assertRouteHeaders("api-1-logs-route-0-method-0", map[string]string{
				"X-Scope-OrgID": "%DYNAMIC_METADATA(auth_gateway_attributes:tenant_id)%",
			})
		}
	}
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func equalStringMaps(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if right[key] != value {
			return false
		}
	}
	return true
}

func TestJWTAuthorizationPolicyCombinationsAreAPIScoped(t *testing.T) {
	c := loadAuthExample(t)
	rules := serverRBACRules(c, c.Servers[0])
	if rules.Policies["api-metrics-write"] == nil || rules.Policies["api-logs"] == nil {
		t.Fatalf("any_of policies did not generate both granted API rules: %#v", rules.Policies)
	}
	metricsGrants := rules.Policies["api-metrics-write"].Principals[0].GetOrIds().Ids
	if len(metricsGrants) != 2 {
		t.Fatalf("metrics API grant principals = %d, want one grant from each issuer", len(metricsGrants))
	}

	c.Servers[0].Authorization = &Authorization{AllOf: []string{"metrics-writers", "logs-writers"}}
	rules = serverRBACRules(c, c.Servers[0])
	if rules.Policies["api-metrics-write"] != nil || rules.Policies["api-logs"] != nil {
		t.Fatalf("all_of policies for disjoint APIs granted access: %#v", rules.Policies)
	}
	if rules.Policies["local-responses"] == nil {
		t.Fatal("all_of denied APIs but removed local 404/405 responses")
	}
}
