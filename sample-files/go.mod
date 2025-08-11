module example.com/mytestproject

go 1.21

require (
	// Gin Web Framework (Check for vulns)
	github.com/gin-gonic/gin v1.7.7 // This version has CVEs

	// Cobra CLI library (Check for vulns)
	github.com/spf13/cobra v1.4.0

	// Logrus logging library (Check for vulns)
	github.com/sirupsen/logrus v1.8.1 // This version has CVEs

	// testify for assertions (Check for vulns)
	github.com/stretchr/testify v1.7.0
)

// You can also have single-line requires
// require github.com/some/other/module v1.2.3
