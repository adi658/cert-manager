/*
Copyright 2019 The Jetstack cert-manager contributors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package acme

import (
	"context"
	"crypto/rsa"
	"fmt"
	"net/url"
	"strings"

	"k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/jetstack/cert-manager/pkg/acme"
	"github.com/jetstack/cert-manager/pkg/acme/client"
	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	logf "github.com/jetstack/cert-manager/pkg/logs"
	"github.com/jetstack/cert-manager/pkg/util/errors"
	"github.com/jetstack/cert-manager/pkg/util/pki"
	acmeapi "github.com/jetstack/cert-manager/third_party/crypto/acme"
)

const (
	errorAccountRegistrationFailed = "ErrRegisterACMEAccount-aditya"
	errorAccountVerificationFailed = "ErrVerifyACMEAccount-aditya"

	successAccountRegistered = "ACMEAccountRegistered-aditya"
	successAccountVerified   = "ACMEAccountVerified-aditya"

	messageAccountRegistrationFailed = "Failed to register ACME account: -aditya"
	messageAccountVerificationFailed = "Failed to verify ACME account: -aditya"
	messageAccountRegistered         = "The ACME account was registered with the ACME server-aditya"
	messageAccountVerified           = "The ACME account was verified with the ACME server-aditya"
)

// Setup will verify an existing ACME registration, or create one if not
// already registered.
func (a *Acme) Setup(ctx context.Context) error {
	log := logf.FromContext(ctx)

	// check if user has specified a v1 account URL, and set a status condition if so.
	if newURL, ok := acmev1ToV2Mappings[a.issuer.GetSpec().ACME.Server]; ok {
		apiutil.SetIssuerCondition(a.issuer, v1alpha1.IssuerConditionReady, v1alpha1.ConditionFalse, "InvalidConfig",
			fmt.Sprintf("Your ACME server URL is set to a v1 endpoint (%s). "+
				"You should update the spec.acme.server field to %q", a.issuer.GetSpec().ACME.Server, newURL))
		// return nil so that Setup only gets called again after the spec is updated
		return nil
	}

	// if the namespace field is not set, we are working on a ClusterIssuer resource
	// therefore we should check for the ACME private key in the 'cluster resource namespace'.
	ns := a.issuer.GetObjectMeta().Namespace
	if ns == "" {
		ns = a.IssuerOptions.ClusterResourceNamespace
	}

	log = logf.WithRelatedResourceName(log, a.issuer.GetSpec().ACME.PrivateKey.Name, ns, "Secret")

	// attempt to obtain the existing private key from the apiserver.
	// if it does not exist then we generate one
	// if it contains invalid data, warn the user and return without error.
	// if any other error occurs, return it and retry.
	pk, err := a.helper.ReadPrivateKey(a.issuer.GetSpec().ACME.PrivateKey, ns)

	switch {
	case apierrors.IsNotFound(err):
		log.Info("generating acme account private key")
		pk, err = a.createAccountPrivateKey(a.issuer.GetSpec().ACME.PrivateKey, ns)
		if err != nil {
			s := messageAccountRegistrationFailed + err.Error()
			apiutil.SetIssuerCondition(a.issuer, v1alpha1.IssuerConditionReady, v1alpha1.ConditionFalse, errorAccountRegistrationFailed, s)
			return fmt.Errorf(s)
		}
		// We clear the ACME account URI as we have generated a new private key
		a.issuer.GetStatus().ACMEStatus().URI = ""

	case errors.IsInvalidData(err):
		apiutil.SetIssuerCondition(a.issuer, v1alpha1.IssuerConditionReady, v1alpha1.ConditionFalse, errorAccountVerificationFailed, fmt.Sprintf("Account private key is invalid: %v", err))
		return nil

	case err != nil:
		s := messageAccountVerificationFailed + err.Error()
		apiutil.SetIssuerCondition(a.issuer, v1alpha1.IssuerConditionReady, v1alpha1.ConditionFalse, errorAccountVerificationFailed, s)
		return fmt.Errorf(s)

	}

	acme.ClearClientCache()

	cl, err := acme.ClientWithKey(a.issuer, pk)
	if err != nil {
		s := messageAccountVerificationFailed + err.Error()
		log.Error(err, "failed to verify acme account")
		a.Recorder.Event(a.issuer, v1.EventTypeWarning, errorAccountVerificationFailed, s)
		apiutil.SetIssuerCondition(a.issuer, v1alpha1.IssuerConditionReady, v1alpha1.ConditionFalse, errorAccountVerificationFailed, s)
		return err
	}

	// TODO: perform a complex check to determine whether we need to verify
	// the existing registration with the ACME server.
	// This should take into account the ACME server URL, as well as a checksum
	// of the private key's contents.
	// Alternatively, we could add 'observed generation' fields here, tracking
	// the most recent copy of the Issuer and Secret resource we have checked
	// already.

	rawServerURL := a.issuer.GetSpec().ACME.Server
	parsedServerURL, err := url.Parse(rawServerURL)
	if err != nil {
		r := "InvalidURL"
		s := fmt.Sprintf("Failed to parse existing ACME server URI %q: %v", rawServerURL, err)
		a.Recorder.Eventf(a.issuer, v1.EventTypeWarning, r, s)
		apiutil.SetIssuerCondition(a.issuer, v1alpha1.IssuerConditionReady, v1alpha1.ConditionFalse, r, s)
		// absorb errors as retrying will not help resolve this error
		return nil
	}

	rawAccountURL := a.issuer.GetStatus().ACMEStatus().URI
	parsedAccountURL, err := url.Parse(rawAccountURL)
	if err != nil {
		r := "InvalidURL"
		s := fmt.Sprintf("Failed to parse existing ACME account URI %q: %v", rawAccountURL, err)
		a.Recorder.Eventf(a.issuer, v1.EventTypeWarning, r, s)
		apiutil.SetIssuerCondition(a.issuer, v1alpha1.IssuerConditionReady, v1alpha1.ConditionFalse, r, s)
		// absorb errors as retrying will not help resolve this error
		return nil
	}

	hasReadyCondition := apiutil.IssuerHasCondition(a.issuer, v1alpha1.IssuerCondition{
		Type:   v1alpha1.IssuerConditionReady,
		Status: v1alpha1.ConditionTrue,
	})

	// If the Host components of the server URL and the account URL match, then
	// we skip re-checking the account status to save excess calls to the
	// ACME api.
	if hasReadyCondition &&
		a.issuer.GetStatus().ACMEStatus().URI != "" &&
		parsedAccountURL.Host == parsedServerURL.Host {
		log.Info("skipping re-verifying ACME account as cached registration " +
			"details look sufficient")
		return nil
	}

	if parsedAccountURL.Host != parsedServerURL.Host {
		log.Info("ACME server URL host and ACME private key registration " +
			"host differ. Re-checking ACME account registration")
		a.issuer.GetStatus().ACMEStatus().URI = ""
	}

	// registerAccount will also verify the account exists if it already
	// exists.
	account, err := a.registerAccount(ctx, cl)
	if err != nil {
		s := messageAccountVerificationFailed + err.Error()
		log.Error(err, "failed to verify ACME account")
		a.Recorder.Event(a.issuer, v1.EventTypeWarning, errorAccountVerificationFailed, s)
		apiutil.SetIssuerCondition(a.issuer, v1alpha1.IssuerConditionReady, v1alpha1.ConditionFalse, errorAccountRegistrationFailed, s)

		acmeErr, ok := err.(*acmeapi.Error)
		// If this is not an ACME error, we will simply return it and retry later
		if !ok {
			return err
		}

		// If the status code is 400 (BadRequest), we will *not* retry this registration
		// as it implies that something about the request (i.e. email address or private key)
		// is invalid.
		if acmeErr.StatusCode >= 400 && acmeErr.StatusCode < 500 {
			log.Error(acmeErr, "skipping retrying account registration as a "+
				"BadRequest response was returned from the ACME server")
			return nil
		}

		// Otherwise if we receive anything other than a 400, we will retry.
		return err
	}

	log.Info("verified existing registration with ACME server")
	apiutil.SetIssuerCondition(a.issuer, v1alpha1.IssuerConditionReady, v1alpha1.ConditionTrue, successAccountRegistered, messageAccountRegistered)
	a.issuer.GetStatus().ACMEStatus().URI = account.URL

	return nil
}

// registerAccount will register a new ACME account with the server. If an
// account with the clients private key already exists, it will attempt to look
// up and verify the corresponding account, and will return that. If this fails
// due to a not found error it will register a new account with the given key.
func (a *Acme) registerAccount(ctx context.Context, cl client.Interface) (*acmeapi.Account, error) {
	// check if the account already exists
	acc, err := cl.GetAccount(ctx)
	if err == nil {
		return acc, nil
	}

	// return all errors except for 404 errors (which indicate the account
	// is not yet registered)
	acmeErr, ok := err.(*acmeapi.Error)
	if !ok || (acmeErr.StatusCode != 400 && acmeErr.StatusCode != 404) {
		return nil, err
	}

	emailurl := []string(nil)
	if a.issuer.GetSpec().ACME.Email != "" {
		emailurl = []string{fmt.Sprintf("mailto:%s", strings.ToLower(a.issuer.GetSpec().ACME.Email))}
	}

	acc = &acmeapi.Account{
		Contact:     emailurl,
		TermsAgreed: true,
	}

	acc, err = cl.CreateAccount(ctx, acc)
	if err != nil {
		return nil, err
	}
	// TODO: re-enable this check once this field is set by Pebble
	// if acc.Status != acme.StatusValid {
	// 	return nil, fmt.Errorf("acme account is not valid")
	// }

	return acc, nil
}

// createAccountPrivateKey will generate a new RSA private key, and create it
// as a secret resource in the apiserver.
func (a *Acme) createAccountPrivateKey(sel v1alpha1.SecretKeySelector, ns string) (*rsa.PrivateKey, error) {
	sel = acme.PrivateKeySelector(sel)
	accountPrivKey, err := pki.GenerateRSAPrivateKey(pki.MinRSAKeySize)
	if err != nil {
		return nil, err
	}

	_, err = a.Client.CoreV1().Secrets(ns).Create(&v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      sel.Name,
			Namespace: ns,
		},

		//accountPrivKey = "-----BEGIN RSA PRIVATE KEY-----MIIEowIBAAKCAQEAuJ3maCh+7c+rWXeAxs7vhzlLjnCGluslCVuwMTEy13fB88wY EGZ8CN90zhnhPj+FOqdTWMzN7e+XLQ0cHlbAqjzmaVYFxSWWaOoYKxiZOEKIaMfV NjykQembBaXMyzt6SKHLyU1llIrln4DxvsUGJo6sg0AINAR5QNrwdVcY0MlwcFY0 vNmdm+9mTNvC8R1fAS+px78nxK+2krjgFl5dqeBIRZJL7I5TaXQKmyfYzj2ScaJY NYvwkl1djktJoAdnRjIVvukiDAcfURVwRx9UOdEDXG4TfqMltf4nG5EgP0tYp5Lq usOpTG59NykPUFIjYW5Rrj0CfqvZMG90S5UgyQIDAQABAoIBAAvihmGwMbOnidVh nxWtXrgq1RVfYxq2GpVGpMoV67r5R7AlNGth3ZxInmFiQyDZv/7tpKzzylIF+Yp5 7JR7az3KW97uHcL6T3uDjni/xaVciyGLs8shDkX7/vHXIZ73vkCMwey8ocx1QKEL EQUB9AppZuuwJJcMrq2hKpezOrK+GRGr1uMDvD+UkKfdfXfRz7ew3TrcfE0EVhpF 0J1M2bSKR4lorTaWb0+rjxD81z0sbefmeVNt3e7XmFYrPGZSxefser9HBZRJIa2E uhtzwSN/3KDMgfSQuMdkqXpoZxN3XjblVW+HkZX070fNkCC7qAYh8QyMDQxdunS5 BqC7rvECgYEA318UoUivQ1ihcER4ru46/fPOkhxk5PvrJHFyNRgkeMTJMu0hqRjJ 9J4gftBc9HtuKhcAekdpJGz8KC+3NGvegIOwdfyWJ0ml9HwawIkxyVcFtXF5p7yR QycCTCdUXkvZ2phdHHBy0ERLBFTjaTuya0A3nlI+6lGJRSbotxascpUCgYEA05WZ pXvk+1fyQzBdajc7e3ozOYtU+NkcuoEm8LR5bGzy6ilm1EN/FRByQ9sPUqKPoV8J 6m+M1yV4EryYLKbzrEjibN12D18BuSSQZsvU3xdm3+3rdJzVTr1/OxBHGquDWeEf VbtMOrD5OdsADi+T9mXnM5pNfFSHUHmwxICtPGUCgYBnMaDxRggaP+cNW8S5ZDwC uNE1NULzeuLOSk7t8oJe/OLK0Tycx2P9y9PNYmufUyq47Tl+RGFxv5va4PhtkmwP yUcLqy6fZenygidFzdwfXUG46ny+nmIpuOrZzc2vZrF1yLAzhEu2peZWUPVi1359 CATp8qs4S4T0Wp5mf2YZ5QKBgQCAfkGo9ezBl09Q7nZMou5EtpmVQMCBv5hqyzRS ycdTyXZcLnh8P+FVcX9zJf3QOVjwrz7eWJA3uFGLT2068MjawAiCBJxGCXSKc2Ie i3rjYNrg8yQi1XvVLc+ultwXnkFOvCDDd9N7cS5prE4ET3CUGp6l//c+ojbq8Hwh WePa4QKBgCdVivwwPml5Lsw6S0DO6EUqjUb6nO2DC6Fa0hmHoK367gB4AmjpBCPU oUX7SnHLg5bbUgEoxkwg06s22VcKS1NKphYMm23ftNK1khoDB3j2IU8JY0HmhiEt mkGqzPr2fLRCfUC8MW40HMenxYi3PJPi+wYHGiI0nVwouaaNniZA-----END RSA PRIVATE KEY-----"
		Data: map[string][]byte{
			sel.Key: pki.EncodePKCS1PrivateKey(accountPrivKey),
		},
	})

	if err != nil {
		return nil, err
	}

	return accountPrivKey, err
}

var acmev1ToV2Mappings = map[string]string{
	"https://acme-v01.api.letsencrypt.org/directory":      "https://acme-v02.api.letsencrypt.org/directory",
	"https://acme-staging.api.letsencrypt.org/directory":  "https://acme-staging-v02.api.letsencrypt.org/directory",
	"https://acme-v01.api.letsencrypt.org/directory/":     "https://acme-v02.api.letsencrypt.org/directory",
	"https://acme-staging.api.letsencrypt.org/directory/": "https://acme-staging-v02.api.letsencrypt.org/directory",
}
