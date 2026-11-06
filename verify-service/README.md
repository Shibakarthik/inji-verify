# Inji Verify Backend Service

### Contents
* Features
* Standards
* Setup Guide
* API docs


#### Features
* ###### VC Verification
  It offers an API for verifying VCs on the server side. The API takes a VC as input and carries out validation and proof verification using the [vc-verifier](https://github.com/mosip/vc-verifier/tree/master/vc-verifier/kotlin) module.

* ###### OpenID4VP Sharing
  It is designed to support OpenID4VP specification. The current supported draft is [draft 21](https://openid.net/specs/openid-4-verifiable-presentations-1_0-21.html).

#### Standards
  For OpenID4VP Sharing below are the supported features.
- Cross Device Flow
- Same Device Flow
- `response_type` as `vp_token`
- `response_mode` as `direct_post`
- Verifiable Presentation proofs supported are `ED25519Signature2018`, `ED25519Signature2020` and `RSASignature2018`

Out of scope items are
- `response_type` with `vp_token id_token`
- `response mode` with `direct_post.jwt
##### Setup Guide

The link to set up guide can be found [here](../Readme.md).

##### API docs

The API docs are published in Stoplight, which can be found [here](https://mosip.stoplight.io/docs/inji-verify/branches/main).


### Optional Trust Registry integration (A.2)

The backend can check issuer authorization against an external Inji Trust Registry during credential verification. The integration is disabled by default to preserve existing deployments. When enabled, a registry timeout or an indeterminate response fails the issuer authorization check; it is never treated as authorization.

For Helm deployments, configure the `trustRegistry` values in `helm/inji-verify-service/values.yaml`:

```yaml
trustRegistry:
  enabled: true
  baseUrl: "https://trust-registry.example.org"
  connectTimeout: 3000
  readTimeout: 3000
```

The URL must be reachable from the Verify backend pod. The public registry check endpoint is used; no Trust Registry administrator credentials are required. The initial implementation extracts issuer DID and the first application-specific type from JSON-LD credentials. Other credential formats currently return an explicit unsupported-format result when the integration is enabled.
