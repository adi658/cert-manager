package main

import (
	"fmt"
	jose "gopkg.in/square/go-jose.v2"
)

func main() {
    fmt.Println("Hello World")
    //RegisterWithExternalAccountBinding(registration.RegisterEABOptions{
    //                    TermsOfServiceAgreed: True,
    //                    Kid:                  'xuc2tdtoGmkt2B2rq9VSqA',
    //                    HmacEncoded:          '8XoZwto2fb1CHspAYMagkyapArcZ9LCZQ-KNRvMd1Cw6ywiSm7qxzAGoBhvFZVnXGvmZtsTqCtaw9_bR1YqUpA',
    //            })
    var url1 string = "https://beta.acme.sectigo.com/v2/DV"
    var kid1 string = "xuc2tdtoGmkt2B2rq9VSqA"
    var hmac1 string = "8XoZwto2fb1CHspAYMagkyapArcZ9LCZQ-KNRvMd1Cw6ywiSm7qxzAGoBhvFZVnXGvmZtsTqCtaw9_bR1YqUpA"
    SignEABContent(url1,kid1,hmac1)
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


type RegisterEABOptions struct {
	TermsOfServiceAgreed bool
	Kid                  string
	HmacEncoded          string
}

// RegisterWithExternalAccountBinding Register the current account to the ACME server.
//func (r *Registrar) RegisterWithExternalAccountBinding(options RegisterEABOptions) (*Resource, error) {
func RegisterWithExternalAccountBinding(options RegisterEABOptions) (*Resource, error) {
	accMsg := acme.Account{
		TermsOfServiceAgreed: options.TermsOfServiceAgreed,
		Contact:              []string{},
	}

	if r.user.GetEmail() != "" {
		log.Infof("acme: Registering account for %s", r.user.GetEmail())
		accMsg.Contact = []string{"mailto:" + r.user.GetEmail()}
	}

	account, err := r.core.Accounts.NewEAB(accMsg, options.Kid, options.HmacEncoded)
	if err != nil {
		errorDetails, ok := err.(acme.ProblemDetails)
		// FIXME seems impossible
		if !ok || errorDetails.HTTPStatus != http.StatusConflict {
			return nil, err
		}
	}

	return &Resource{URI: account.Location, Body: account.Account}, nil
}

// NewEAB Creates a new account with an External Account Binding.
func (a *AccountService) NewEAB(accMsg acme.Account, kid string, hmacEncoded string) (acme.ExtendedAccount, error) {
	hmac, err := base64.RawURLEncoding.DecodeString(hmacEncoded)
	if err != nil {
		return acme.ExtendedAccount{}, fmt.Errorf("acme: could not decode hmac key: %v", err)
	}

	eabJWS, err := a.core.signEABContent(a.core.GetDirectory().NewAccountURL, kid, hmac)
	if err != nil {
		return acme.ExtendedAccount{}, fmt.Errorf("acme: error signing eab content: %v", err)
	}
	accMsg.ExternalAccountBinding = eabJWS

	return a.New(accMsg)
}

func (j *JWS) SignEABContent(url, kid string, hmac []byte) (*jose.JSONWebSignature, error) {
	jwk := jose.JSONWebKey{Key: j.privKey}
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

