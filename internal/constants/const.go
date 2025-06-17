package constants

// DBIndexField database default constants
const (
	DBIndexField = "id"
)

// MaxPageLimit You can find out through the following link
// https://stackoverflow.com/questions/25265465/why-github-api-gives-me-a-lower-number-stars-of-a-repo
const (
	GitHubStarBaseURL = "https://api.github.com/repos"
	GithubUserAPIURL  = "https://api.github.com/user"
	DefaultPageSize   = 100 // The maximum value cannot exceed 100
	MaxPageLimit      = 400 // Maximum number of pages to fetch
)

// login status constants
const (
	LoginStatusLoggedIn  = "logged_in"
	LoginStatusLoggedOut = "logged_out"
)

// Binding account related
const (
	BindAccountCallbackPath = "/oidc_auth/manager/bind/account/callback"
	LoginSuccessPath        = "/login/success"
)

// Casdoor certification related
const (
	CasdoorAuthURI         = "/login/oauth/authorize"
	CasdoorTokenURI        = "/api/login/oauth/access_token"
	CasdoorRefreshTokenURI = "/api/login/oauth/refresh_token"
)
