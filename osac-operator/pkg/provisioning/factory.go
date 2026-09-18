package provisioning

import (
	"fmt"
	"net/url"
	"time"
)

// ProviderConfig contains configuration for creating the AAP provisioning provider.
type ProviderConfig struct {
	AAPClient           AAPClient
	ProvisionTemplate   string
	DeprovisionTemplate string
	// FulfillmentEndpoint and FulfillmentIssuerURL are forwarded to AAP for
	// tenant-cluster CSI provisioning. They are deployment configuration, not
	// credentials.
	FulfillmentEndpoint  string
	FulfillmentIssuerURL string

	// TemplatePrefix enables convention-based template name resolution for AAP.
	// When set, template names are derived from the resource Kind:
	//   {prefix}-create-{kind-kebab} and {prefix}-delete-{kind-kebab}
	// Explicit ProvisionTemplate/DeprovisionTemplate take precedence when set.
	TemplatePrefix string
}

// NewProvider creates an AAP provisioning provider from the configuration.
func NewProvider(config ProviderConfig) (ProvisioningProvider, error) {
	if config.AAPClient == nil {
		return nil, fmt.Errorf("AAP provider requires AAPClient")
	}
	if (config.FulfillmentEndpoint == "") != (config.FulfillmentIssuerURL == "") {
		return nil, fmt.Errorf("AAP provider requires both FulfillmentEndpoint and FulfillmentIssuerURL")
	}
	if config.FulfillmentIssuerURL != "" {
		issuerURL, err := url.Parse(config.FulfillmentIssuerURL)
		if err != nil || issuerURL.Scheme != "https" || issuerURL.Host == "" {
			return nil, fmt.Errorf("AAP provider requires FulfillmentIssuerURL to be an absolute HTTPS URL")
		}
	}
	return &AAPProvider{
		client:               config.AAPClient,
		provisionTemplate:    config.ProvisionTemplate,
		deprovisionTemplate:  config.DeprovisionTemplate,
		templatePrefix:       config.TemplatePrefix,
		fulfillmentEndpoint:  config.FulfillmentEndpoint,
		fulfillmentIssuerURL: config.FulfillmentIssuerURL,
	}, nil
}

const (
	// DefaultStatusPollInterval is the default interval for polling provider status.
	DefaultStatusPollInterval = 30 * time.Second

	// DefaultMaxJobHistory is the default number of jobs to keep per job array.
	DefaultMaxJobHistory = 10
)
