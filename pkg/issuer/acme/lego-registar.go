package registration

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"encoding/base64"

	"github.com/go-acme/lego/acme/api/internal/nonces"
	"github.com/go-acme/lego/acme"
	"github.com/go-acme/lego/acme/api"
	jose "gopkg.in/square/go-jose.v2"
)

// Resource represents all important information about a registration
// of which the client needs to keep track itself.
// Deprecated: will be remove in the future (acme.ExtendedAccount).
type Resource struct {
	Body acme.Account `json:"body,omitempty"`
	URI  string       `json:"uri,omitempty"`
}

type RegisterOptions struct {
	TermsOfServiceAgreed bool
}

type RegisterEABOptions struct {
	TermsOfServiceAgreed bool
	Kid                  string
	HmacEncoded          string
}

type Registrar struct {
	core *api.Core
	//user User
}

/*
func NewRegistrar(core *api.Core, user User) *Registrar {
	return &Registrar{
		core: core,
		user: user,
	}
}
*/

/*
// Register the current account to the ACME server.
func Register(options RegisterOptions) (*Resource, error) {
	if r == nil || r.user == nil {
		return nil, errors.New("acme: cannot register a nil client or user")
	}

	accMsg := acme.Account{
		TermsOfServiceAgreed: options.TermsOfServiceAgreed,
		Contact:              []string{},
	}

	if r.user.GetEmail() != "" {
		log.Infof("acme: Registering account for %s", r.user.GetEmail())
		accMsg.Contact = []string{"mailto:" + r.user.GetEmail()}
	}

	account, err := r.core.Accounts.New(accMsg)
	if err != nil {
		// FIXME seems impossible
		errorDetails, ok := err.(acme.ProblemDetails)
		if !ok || errorDetails.HTTPStatus != http.StatusConflict {
			return nil, err
		}
	}

	return &Resource{URI: account.Location, Body: account.Account}, nil
}
*/

// RegisterWithExternalAccountBinding Register the current account to the ACME server.
func RegisterWithExternalAccountBinding(options RegisterEABOptions) (*Resource, error) {
	accMsg := acme.Account{
		TermsOfServiceAgreed: options.TermsOfServiceAgreed,
		Contact:              []string{},
	}

	/*
	if user.GetEmail() != "" {
		log.Infof("acme: Registering account for %s", user.GetEmail())
		accMsg.Contact = []string{"mailto:" + user.GetEmail()}
	}

	account, err := r.core.Accounts.NewEAB(accMsg, options.Kid, options.HmacEncoded)
	if err != nil {
		errorDetails, ok := err.(acme.ProblemDetails)
		// FIXME seems impossible
		if !ok || errorDetails.HTTPStatus != http.StatusConflict {
			return nil, err
		}
	}
	*/

	//########
	accMsg.Contact = []string{"mailto: aditya.bhangle@trianz.com"}
	account, err := NewEAB(accMsg, options.Kid, options.HmacEncoded)

	return &Resource{URI: account.Location, Body: account.Account}, nil
}

/*
// QueryRegistration runs a POST request on the client's registration and returns the result.
//
// This is similar to the Register function,
// but acting on an existing registration link and resource.
func  QueryRegistration() (*Resource, error) {
	if r == nil || r.user == nil {
		return nil, errors.New("acme: cannot query the registration of a nil client or user")
	}

	// Log the URL here instead of the email as the email may not be set
	log.Infof("acme: Querying account for %s", r.user.GetRegistration().URI)

	account, err := r.core.Accounts.Get(r.user.GetRegistration().URI)
	if err != nil {
		return nil, err
	}

	return &Resource{
		Body: account,
		// Location: header is not returned so this needs to be populated off of existing URI
		URI: r.user.GetRegistration().URI,
	}, nil
}


// DeleteRegistration deletes the client's user registration from the ACME server.
func (r *Registrar) DeleteRegistration() error {
	if r == nil || r.user == nil {
		return errors.New("acme: cannot unregister a nil client or user")
	}

	log.Infof("acme: Deleting account for %s", r.user.GetEmail())

	return r.core.Accounts.Deactivate(r.user.GetRegistration().URI)
}

// ResolveAccountByKey will attempt to look up an account using the given account key
// and return its registration resource.
func (r *Registrar) ResolveAccountByKey() (*Resource, error) {
	log.Infof("acme: Trying to resolve account by key")

	accMsg := acme.Account{OnlyReturnExisting: true}
	accountTransit, err := r.core.Accounts.New(accMsg)
	if err != nil {
		return nil, err
	}

	account, err := r.core.Accounts.Get(accountTransit.Location)
	if err != nil {
		return nil, err
	}

	return &Resource{URI: accountTransit.Location, Body: account}, nil
}
*/

// NewEAB Creates a new account with an External Account Binding.
func  NewEAB(accMsg acme.Account, kid string, hmacEncoded string) (acme.ExtendedAccount, error) {
	hmac, err := base64.RawURLEncoding.DecodeString(hmacEncoded)
	if err != nil {
		return acme.ExtendedAccount{}, fmt.Errorf("acme: could not decode hmac key: %v", err)
	}
	accountURL = "https://beta.acme.sectigo.com/v2/DV" 
	eabJWS, err := signEABContent(accountURL, kid, hmac)
	if err != nil {
		return acme.ExtendedAccount{}, fmt.Errorf("acme: error signing eab content: %v", err)
	}
	accMsg.ExternalAccountBinding = eabJWS

	return New(accMsg)
}

// JWS Represents a JWS.
type JWS struct {
	privKey crypto.PrivateKey
	kid     string // Key identifier
	nonces  *nonces.Manager
}

// NewJWS Create a new JWS.
func NewJWS(privateKey crypto.PrivateKey, kid string, nonceManager *nonces.Manager) *JWS {
	return &JWS{
		privKey: privateKey,
		nonces:  nonceManager,
		kid:     kid,
	}
}

// SignEABContent Signs an external account binding content with the JWS.
func SignEABContent(url, kid string, hmac []byte) (*jose.JSONWebSignature, error) {
	jwk := jose.JSONWebKey{Key: privKey}
	jwkJSON, err := jwk.Public().MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("acme: error encoding eab jwk key: %v", err)
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.HS256, Key: hmac},
		&jose.SignerOptions{
			EmbedJWK: false,
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				"kid": kid,
				"url": url,
			},
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create External Account Binding jose signer -> %v", err)
	}

	signed, err := signer.Sign(jwkJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to External Account Binding sign content -> %v", err)
	}

	return signed, nil
}

