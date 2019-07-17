package main

import (
	"crypto"
	"fmt"

	jose "gopkg.in/square/go-jose.v2"
)

import "github.com/go-acme/lego/acme/api/internal/nonces"


type JWS struct {
	privKey crypto.PrivateKey
	kid     string // Key identifier
	//nonces  *nonces.Manager
}

func SignEABContent(url, kid string, hmac []byte) (*jose.JSONWebSignature, error) {
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
    //SignEABContent(url1,kid1,hmac1)
    //abJWS, err := a.core.signEABContent(a.core.GetDirectory().NewAccountURL, kid, hmac)
    //abJWS, err := SignEABContent(url1,kid1,hmac1)

}

