package main

import (
	"fmt"
	"crypto"
	"net/http"
	"encoding/base64"
	"github.com/go-acme/lego/acme"
	jose "gopkg.in/square/go-jose.v2"
	//"github.com/go-acme/lego/acme/api/internal/nonces"
	"github.com/adi658/cert-manager/pkg/issuer/acme/nonces"
)

type Resource struct {
	Body acme.Account `json:"body,omitempty"`
	URI  string       `json:"uri,omitempty"`
}

type RegisterEABOptions struct {
	TermsOfServiceAgreed bool
	Kid                  string
	HmacEncoded          string
}

type JWS struct {
	privKey crypto.PrivateKey
	kid     string // Key identifier
	//nonces  *nonces.Manager
}

func Main() {
	kid := "xuc2tdtoGmkt2B2rq9VSqA"
	hmacEncoded := "8XoZwto2fb1CHspAYMagkyapArcZ9LCZQ-KNRvMd1Cw6ywiSm7qxzAGoBhvFZVnXGvmZtsTqCtaw9_bR1YqUpA"
	RegisterWithExternalAccountBinding(RegisterEABOptions{
                        TermsOfServiceAgreed: true,
                        Kid:                  kid,
                        HmacEncoded:          hmacEncoded,
        })
}

// RegisterWithExternalAccountBinding Register the current account to the ACME server.
func RegisterWithExternalAccountBinding(options RegisterEABOptions) (*Resource, error) {
	accMsg := acme.Account{
		TermsOfServiceAgreed: options.TermsOfServiceAgreed,
		Contact:              []string{},
	}

	accMsg.Contact = []string{"mailto: aditya.bhangle@trianz.com"}

	account, err := NewEAB(accMsg, options.Kid, options.HmacEncoded)
	if err != nil {
		errorDetails, ok := err.(acme.ProblemDetails)
		// FIXME seems impossible
		if !ok || errorDetails.HTTPStatus != http.StatusConflict {
			return nil, err
		}
	}
	return &Resource{URI: account.Location, Body: account.Account}, nil
}

/*
// NewEAB Creates a new account with an External Account Binding.
func NewEAB(accMsg acme.Account, kid string, hmacEncoded string) (acme.ExtendedAccount, error) {
	hmac, err := base64.RawURLEncoding.DecodeString(hmacEncoded)
	if err != nil {
		return acme.ExtendedAccount{}, fmt.Errorf("acme: could not decode hmac key: %v", err)
	}

	eabJWS, err := SignEABContent(NewAccountURL, kid, hmac)

	if err != nil {
		return acme.ExtendedAccount{}, fmt.Errorf("acme: error signing eab content: %v", err)
	}
	accMsg.ExternalAccountBinding = eabJWS

	return New(accMsg)
}
*/

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

/*
func post(uri string, reqBody, response interface{}) (*http.Response, error) {
	content, err := json.Marshal(reqBody)
	if err != nil {
		return nil, errors.New("failed to marshal message")
	}

	return retrievablePost(uri, content, response)
}
*/

/*
// New Creates a new account.
func  New(req acme.Account) (acme.ExtendedAccount, error) {
	var account acme.Account
	resp, err := ("temp", req, &account)
	location := getLocation(resp)

	if len(location) > 0 {
		SetKid(location)
	}

	if err != nil {
		return acme.ExtendedAccount{Location: location}, err
	}

	return acme.ExtendedAccount{Account: account, Location: location}, nil
}
*/


/*
func handleTOS(ctx *cli.Context, client *lego.Client) bool {
	// Check for a global accept override
	if ctx.GlobalBool("accept-tos") {
		return true
	}

	reader := bufio.NewReader(os.Stdin)
	log.Printf("Please review the TOS at %s", client.GetToSURL())

	for {
		fmt.Println("Do you accept the TOS? Y/n")
		text, err := reader.ReadString('\n')
		if err != nil {
			log.Fatalf("Could not read from console: %v", err)
		}

		text = strings.Trim(text, "\r\n")
		switch text {
		case "", "y", "Y":
			return true
		case "n", "N":
			return false
		default:
			fmt.Println("Your input was invalid. Please answer with one of Y/y, n/N or by pressing enter.")
		}
	}
}

func register(ctx *cli.Context, client *lego.Client) (*registration.Resource, error) {
	accepted := handleTOS(ctx, client)
	if !accepted {
		log.Fatal("You did not accept the TOS. Unable to proceed.")
	}

	if ctx.GlobalBool("eab") {
		kid := ctx.GlobalString("kid")
		hmacEncoded := ctx.GlobalString("hmac")

		if kid == "" || hmacEncoded == "" {
			log.Fatalf("Requires arguments --kid and --hmac.")
		}

		return client.Registration.RegisterWithExternalAccountBinding(registration.RegisterEABOptions{
			TermsOfServiceAgreed: accepted,
			Kid:                  kid,
			HmacEncoded:          hmacEncoded,
		})
	}

	return client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
}
*/
