/*
Copyright 2026.

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

package controller

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"

	common_helper "github.com/openstack-k8s-operators/lib-common/modules/common/helper"
	apiv1beta1 "github.com/openstack-lightspeed/operator/api/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

type caCert struct {
	hash   [sha256.Size]byte
	cert   *x509.Certificate
	expire time.Time
}

type caBundle struct {
	certs []caCert
}

// getOperatorCABundle reads the system CA bundle from the operator pod's filesystem.
// Tries the RHEL path first, falls back to Debian/Ubuntu path.
var getOperatorCABundle = func() ([]byte, error) {
	contents, err := os.ReadFile(DownstreamTLSCABundlePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			contents, err = os.ReadFile(UpstreamTLSCABundlePath)
			if err != nil {
				return nil, fmt.Errorf("failed to read system CA bundle: %w", err)
			}
			return contents, nil
		}
		return nil, fmt.Errorf("failed to read downstream CA bundle: %w", err)
	}
	return contents, nil
}

// getCertsFromPEM parses PEM data and adds valid certificates to the bundle.
// Rejects non-CERTIFICATE blocks and invalid X.509 data. Skips expired certs.
// Deduplicates by SHA256 hash of the raw DER bytes.
func (cab *caBundle) getCertsFromPEM(pemData []byte) error {
	if pemData == nil {
		return fmt.Errorf("certificate data is nil")
	}

	rest := pemData
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}

		if block.Type != "CERTIFICATE" {
			return fmt.Errorf("invalid PEM block type %q: only CERTIFICATE blocks are permitted", block.Type)
		}

		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("invalid certificate: %w", err)
		}

		if time.Now().After(certificate.NotAfter) {
			continue
		}

		blockHash := sha256.Sum256(block.Bytes)
		isDuplicate := false
		for _, existing := range cab.certs {
			if existing.hash == blockHash {
				isDuplicate = true
				break
			}
		}
		if !isDuplicate {
			cab.certs = append(cab.certs, caCert{
				hash:   blockHash,
				cert:   certificate,
				expire: certificate.NotAfter,
			})
		}
	}

	return nil
}

// encodePEM encodes all certificates in the bundle back to PEM format.
func (cab *caBundle) encodePEM() []byte {
	var result []byte
	for _, c := range cab.certs {
		block := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: c.cert.Raw,
		}
		result = append(result, pem.EncodeToMemory(block)...)
	}
	return result
}

// reconcileCombinedCABundleConfigMap builds a combined CA bundle from the operator's
// system CAs and the user-provided CA ConfigMap, then creates/updates the managed
// ConfigMap that gets mounted into application pods.
func reconcileCombinedCABundleConfigMap(h *common_helper.Helper, ctx context.Context, instance *apiv1beta1.OpenStackLightspeed) error {
	logger := h.GetLogger()
	bundle := &caBundle{}

	systemCAs, err := getOperatorCABundle()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrReadSystemCABundle, err)
	}
	if err := bundle.getCertsFromPEM(systemCAs); err != nil {
		return fmt.Errorf("%w: %v", ErrParseSystemCABundle, err)
	}

	if instance.Spec.TLSCACertBundle != "" {
		userCM := &corev1.ConfigMap{}
		err := h.GetClient().Get(ctx, client.ObjectKey{
			Name:      instance.Spec.TLSCACertBundle,
			Namespace: h.GetBeforeObject().GetNamespace(),
		}, userCM)
		if err != nil {
			return fmt.Errorf("%w %q: %v", ErrGetAdditionalCACM, instance.Spec.TLSCACertBundle, err)
		}

		for key, certData := range userCM.Data {
			if err := bundle.getCertsFromPEM([]byte(certData)); err != nil {
				return fmt.Errorf("%w: key %q in ConfigMap %q: %v", ErrParseUserCA, key, instance.Spec.TLSCACertBundle, err)
			}
		}
		logger.Info("user CA certificates merged", "configmap", instance.Spec.TLSCACertBundle)
	}

	bundlePEM := bundle.encodePEM()

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      CombinedCABundleConfigMapName,
			Namespace: h.GetBeforeObject().GetNamespace(),
		},
	}

	result, err := controllerutil.CreateOrPatch(ctx, h.GetClient(), cm, func() error {
		cm.Data = map[string]string{
			CombinedCABundleKey: string(bundlePEM),
		}
		return controllerutil.SetControllerReference(h.GetBeforeObject(), cm, h.GetScheme())
	})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCreateCombinedCABundle, err)
	}

	logger.Info("combined CA bundle ConfigMap reconciled", "name", cm.Name, "result", result, "certCount", len(bundle.certs))
	return nil
}
