package gateway

import (
	"net/http"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/graphql-go-tools/pkg/graphql"

	"github.com/TykTechnologies/tyk/user"
)

func TestGraphQLComplexityMiddleware_DepthLimitEnabled(t *testing.T) {
	m := GraphqlComplexityChecker{logger: logrus.NewEntry(log)}

	accessDefPerField := &user.AccessDefinition{
		FieldAccessRights: []user.FieldAccessDefinition{
			{TypeName: "Query", FieldName: "countries", Limits: user.FieldLimits{MaxQueryDepth: 0}},
			{TypeName: "Query", FieldName: "continents", Limits: user.FieldLimits{MaxQueryDepth: -1}},
			{TypeName: "Mutation", FieldName: "putCountry", Limits: user.FieldLimits{MaxQueryDepth: 2}},
		},
		Limit: user.APILimit{
			MaxQueryDepth: 0,
		},
	}

	accessDefWithGlobal := &user.AccessDefinition{
		Limit: user.APILimit{
			MaxQueryDepth: 2,
		},
	}

	t.Run("Per field", func(t *testing.T) {
		assert.True(t, m.DepthLimitEnabled(accessDefPerField))
		accessDefPerField.FieldAccessRights = []user.FieldAccessDefinition{}
		assert.False(t, m.DepthLimitEnabled(accessDefPerField))
	})

	t.Run("Global", func(t *testing.T) {
		assert.True(t, m.DepthLimitEnabled(accessDefWithGlobal))
		accessDefWithGlobal.Limit.MaxQueryDepth = 0
		assert.False(t, m.DepthLimitEnabled(accessDefWithGlobal))
	})
}

func TestGraphQLComplexityMiddleware_DepthLimitExceeded(t *testing.T) {
	m := GraphqlComplexityChecker{logger: logrus.NewEntry(log)}
	countriesSchema, err := graphql.NewSchemaFromString(gqlCountriesSchema)
	require.NoError(t, err)

	// global depth: 4 countries depth: 3
	countriesQuery := `query TestQuery { countries { code name continent { code name countries { code name } } }}`

	// global depth: 5 countries depth: 3 continents depth: 4
	countriesContinentsQuery := `query TestQuery { 
		countries { continent { countries { name } } }
		continents { countries { continent { countries { name } } } }
	}`

	cases := []struct {
		name          string
		operationName string
		query         string
		accessDef     *user.AccessDefinition
		result        ComplexityFailReason
	}{
		{
			name:          "should use global limit and exceed when no per field rights",
			operationName: "TestQuery",
			query:         countriesQuery,
			accessDef: &user.AccessDefinition{
				Limit:             user.APILimit{MaxQueryDepth: 3},
				FieldAccessRights: []user.FieldAccessDefinition{},
			},
			result: ComplexityFailReasonDepthLimitExceeded,
		},
		{
			name:          "should respect unlimited specific field depth limit and not exceed",
			operationName: "TestQuery",
			query:         countriesQuery,
			accessDef: &user.AccessDefinition{
				Limit: user.APILimit{MaxQueryDepth: 3},
				FieldAccessRights: []user.FieldAccessDefinition{
					{
						TypeName: "Query", FieldName: "countries",
						Limits: user.FieldLimits{MaxQueryDepth: -1},
					},
				},
			},
			result: ComplexityFailReasonNone,
		},
		{
			name:          "should respect higher specific field depth limit and not exceed",
			operationName: "TestQuery",
			query:         countriesQuery,
			accessDef: &user.AccessDefinition{
				Limit: user.APILimit{MaxQueryDepth: 3},
				FieldAccessRights: []user.FieldAccessDefinition{
					{
						TypeName: "Query", FieldName: "countries",
						Limits: user.FieldLimits{MaxQueryDepth: 10},
					},
				},
			},
			result: ComplexityFailReasonNone,
		},
		{
			name:          "should respect lower specific field depth limit and exceed",
			operationName: "TestQuery",
			query:         countriesQuery,
			accessDef: &user.AccessDefinition{
				Limit: user.APILimit{MaxQueryDepth: 100},
				FieldAccessRights: []user.FieldAccessDefinition{
					{
						TypeName: "Query", FieldName: "countries",
						Limits: user.FieldLimits{MaxQueryDepth: 1},
					},
				},
			},
			result: ComplexityFailReasonDepthLimitExceeded,
		},
		{
			name:          "should respect specific field depth limits and not exceed",
			operationName: "TestQuery",
			query:         countriesContinentsQuery,
			accessDef: &user.AccessDefinition{
				Limit: user.APILimit{MaxQueryDepth: 1},
				FieldAccessRights: []user.FieldAccessDefinition{
					{
						TypeName: "Query", FieldName: "countries",
						Limits: user.FieldLimits{MaxQueryDepth: 3},
					},
					{
						TypeName: "Query", FieldName: "continents",
						Limits: user.FieldLimits{MaxQueryDepth: 4},
					},
				},
			},
			result: ComplexityFailReasonNone,
		},
		{
			name:          "should fallback to global limit when continents limits is not specified",
			operationName: "TestQuery",
			query:         countriesContinentsQuery,
			accessDef: &user.AccessDefinition{
				Limit: user.APILimit{MaxQueryDepth: 1},
				FieldAccessRights: []user.FieldAccessDefinition{
					{
						TypeName: "Query", FieldName: "countries",
						Limits: user.FieldLimits{MaxQueryDepth: 3},
					},
				},
			},
			result: ComplexityFailReasonDepthLimitExceeded,
		},
		{
			name:          "should fallback to global limit when countries limits is not specified",
			operationName: "TestQuery",
			query:         countriesContinentsQuery,
			accessDef: &user.AccessDefinition{
				Limit: user.APILimit{MaxQueryDepth: 1},
				FieldAccessRights: []user.FieldAccessDefinition{
					{
						TypeName: "Query", FieldName: "continents",
						Limits: user.FieldLimits{MaxQueryDepth: 4},
					},
				},
			},
			result: ComplexityFailReasonDepthLimitExceeded,
		},
		{
			name:          "should allow schema introspection query and ignore depth limit",
			operationName: "IntrospectionQuery",
			query:         gqlIntrospectionQuery,
			accessDef: &user.AccessDefinition{
				Limit:             user.APILimit{MaxQueryDepth: 1},
				FieldAccessRights: []user.FieldAccessDefinition{},
			},
			result: ComplexityFailReasonNone,
		},
		{
			name:          "should disallow schema introspection query and apply depth-limit with other non-introspection fields",
			operationName: "IntrospectionQuery",
			query:         gqlSchemaIntrospectionQueryWithMultipleFields,
			accessDef: &user.AccessDefinition{
				Limit:             user.APILimit{MaxQueryDepth: 1},
				FieldAccessRights: []user.FieldAccessDefinition{},
			},
			result: ComplexityFailReasonDepthLimitExceeded,
		},
		{
			name:          "should allow type introspection query and ignore depth limit",
			operationName: "IntrospectionQuery",
			query:         gqlCountriesTypeIntrospectionQuery,
			accessDef: &user.AccessDefinition{
				Limit:             user.APILimit{MaxQueryDepth: 1},
				FieldAccessRights: []user.FieldAccessDefinition{},
			},
			result: ComplexityFailReasonNone,
		},
		{
			name:          "should disallow type introspection query and apply depth-limit with other non-introspection fields",
			operationName: "IntrospectionQuery",
			query:         gqlCountriesTypeIntrospectionQueryWithMultipleFields,
			accessDef: &user.AccessDefinition{
				Limit:             user.APILimit{MaxQueryDepth: 1},
				FieldAccessRights: []user.FieldAccessDefinition{},
			},
			result: ComplexityFailReasonDepthLimitExceeded,
		},
		{
			name:          "should allow silent introspection query and ignore depth limit",
			operationName: "",
			query:         gqlCountriesSilentTypeIntrospectionQuery,
			accessDef: &user.AccessDefinition{
				Limit:             user.APILimit{MaxQueryDepth: 1},
				FieldAccessRights: []user.FieldAccessDefinition{},
			},
			result: ComplexityFailReasonNone,
		},
		{
			name:          "should return error when complexity fails because of internal reasons",
			operationName: "TestQuery",
			query:         gqlInvalidCountriesQuery,
			accessDef: &user.AccessDefinition{
				Limit:             user.APILimit{MaxQueryDepth: 1},
				FieldAccessRights: []user.FieldAccessDefinition{},
			},
			result: ComplexityFailReasonInternalError,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := &graphql.Request{
				OperationName: tc.operationName,
				Variables:     nil,
				Query:         tc.query,
			}

			failReason := m.DepthLimitExceeded(req, tc.accessDef, countriesSchema)
			assert.Equal(t, tc.result, failReason)

		})
	}
}

func TestGraphQLComplexityMiddleware_ProcessRequest_GraphqlLimits(t *testing.T) {
	countriesSchema, err := graphql.NewSchemaFromString(gqlCountriesSchema)
	require.NoError(t, err)

	apiSpec := BuildAPI(func(spec *APISpec) {
		spec.GraphQL.Enabled = true
		spec.GraphQL.Schema = gqlCountriesSchema
		spec.GraphQLExecutor.Schema = countriesSchema
	})[0]
	m := GraphQLComplexityMiddleware{
		&BaseMiddleware{
			Spec: apiSpec,
		},
	}
	gqlReq := &graphql.Request{
		OperationName: "TestQuery",
		Variables:     nil,
		Query:         `query TestQuery { countries { code name continent { code name countries { code name } } }}`,
	}
	httpReq := &http.Request{}
	ctxSetGraphQLRequest(httpReq, gqlReq)

	session := user.NewSessionState()
	session.MaxQueryDepth = 3
	ctxSetSession(httpReq, session, false, false)

	cases := []struct {
		name   string
		rights map[string]user.AccessDefinition
		result int
	}{
		{
			name:   "should fail when no access rights for the given spec",
			rights: map[string]user.AccessDefinition{"any": {}},
			result: http.StatusInternalServerError,
		},
		{
			name: "should take limit from access rights and fail",
			rights: map[string]user.AccessDefinition{
				apiSpec.APIID: {
					Limit: user.APILimit{MaxQueryDepth: 1},
				},
			},
			result: http.StatusForbidden,
		},
		{
			name: "should take field limits from access rights and proceed",
			rights: map[string]user.AccessDefinition{
				apiSpec.APIID: {
					FieldAccessRights: []user.FieldAccessDefinition{
						{
							TypeName: "Query", FieldName: "countries",
							Limits: user.FieldLimits{MaxQueryDepth: 3},
						},
					},
				},
			},
			result: http.StatusOK,
		},
		{
			name: "should take limit from session and fail when access rights with not matching field and empty limit",
			rights: map[string]user.AccessDefinition{
				apiSpec.APIID: {
					FieldAccessRights: []user.FieldAccessDefinition{
						{
							TypeName: "Query", FieldName: "continents",
							Limits: user.FieldLimits{MaxQueryDepth: 4},
						},
					},
				},
			},
			result: http.StatusForbidden,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			session.AccessRights = tc.rights
			_, failReason := m.ProcessRequest(nil, httpReq, nil)
			assert.Equal(t, tc.result, failReason)
		})
	}
}

const gqlSchemaIntrospectionQueryWithMultipleFields = `query IntrospectionQuery {
  countries {
    name
    continent {
      code
      name
      countries {
        code
      }
    }
  }
  __schema {
    queryType {
      name
    }
  }
}`

const gqlCountriesTypeIntrospectionQuery = `query IntrospectionQuery {
  __type(name:"Country") {
    name
    fields {
      name
      type {
        kind
      }
    }
  }
}`

const gqlCountriesSilentTypeIntrospectionQuery = `{
  __type(name:"Country") {
    name
    fields {
      name
      type {
        kind
      }
    }
  }
}`

const gqlCountriesTypeIntrospectionQueryWithMultipleFields = `query IntrospectionQuery {
  countries {
    name
    continent {
      code
      name
      countries {
        code
      }
    }
  }
  __type(name:"Country") {
    name
  }
}`

const gqlInvalidCountriesQuery = `{
  countries {
    name
    continent {
      code
      name
      countries {
        code
      }
    }
}`
