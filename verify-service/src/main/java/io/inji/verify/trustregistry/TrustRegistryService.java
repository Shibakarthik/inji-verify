package io.inji.verify.trustregistry;

import io.inji.verify.dto.verification.IssuerAuthorizationCheckDto;
import io.mosip.vercred.vcverifier.constants.CredentialFormat;
import lombok.extern.slf4j.Slf4j;
import org.json.JSONArray;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Slf4j
@Service
public class TrustRegistryService {

    private final TrustRegistryClient client;
    private final boolean enabled;

    public TrustRegistryService(
            TrustRegistryClient client,
            @Value("${inji.verify.trust-registry.enabled:false}") boolean enabled) {
        this.client = client;
        this.enabled = enabled;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public IssuerAuthorizationCheckDto checkIssuerAuthorization(String credential, CredentialFormat format) {
        if (!enabled) {
            return new IssuerAuthorizationCheckDto(false, null, null, null, "DISABLED", null, null);
        }

        if (format != CredentialFormat.LDP_VC) {
            return failed(null, null, "UNSUPPORTED_CREDENTIAL_FORMAT",
                    "Trust Registry metadata extraction currently supports JSON-LD credentials only.");
        }

        final String issuerId;
        final String credentialType;
        try {
            JSONObject vc = new JSONObject(credential);
            Object issuer = vc.opt("issuer");
            if (issuer instanceof JSONObject issuerObject) {
                issuerId = issuerObject.optString("id", null);
            } else if (issuer instanceof String issuerString) {
                issuerId = issuerString;
            } else {
                issuerId = null;
            }

            Object type = vc.opt("type");
            if (type instanceof String typeString) {
                credentialType = "VerifiableCredential".equals(typeString) ? null : typeString;
            } else if (type instanceof JSONArray typeArray) {
                credentialType = extractApplicationCredentialType(typeArray);
            } else {
                credentialType = null;
            }
        } catch (Exception ex) {
            return failed(null, null, "CREDENTIAL_METADATA_INVALID",
                    "Unable to read issuer and credential type from the JSON-LD credential.");
        }

        if (issuerId == null || issuerId.isBlank() || credentialType == null || credentialType.isBlank()) {
            return failed(issuerId, credentialType, "CREDENTIAL_METADATA_MISSING",
                    "Credential must contain an issuer DID and an application-specific type.");
        }

        try {
            TrustRegistryResponseDto response = client.checkAuthorization(issuerId, credentialType);
            if (response == null || response.getAuthorised() == null) {
                return failed(issuerId, credentialType, "INVALID_REGISTRY_RESPONSE",
                        "Trust Registry returned an incomplete authorization response.");
            }
            return new IssuerAuthorizationCheckDto(true, response.getAuthorised(),
                    issuerId, credentialType, response.getReason(),
                    response.getEvaluatedAt(), null);
        } catch (Exception ex) {
            log.warn("Unable to evaluate issuer authorization for issuer {} and type {}: {}",
                    issuerId, credentialType, ex.getMessage());
            return failed(issuerId, credentialType, "REGISTRY_UNAVAILABLE",
                    "Trust Registry could not be reached or returned an error.");
        }
    }

    private String extractApplicationCredentialType(JSONArray types) {
        for (int i = 0; i < types.length(); i++) {
            Object value = types.opt(i);
            if (value instanceof String type && !type.isBlank()
                    && !"VerifiableCredential".equals(type)) {
                return type;
            }
        }
        return null;
    }

    private IssuerAuthorizationCheckDto failed(String issuerId, String credentialType,
                                               String reason, String error) {
        return new IssuerAuthorizationCheckDto(true, false, issuerId,
                credentialType, reason, null, error);
    }
}
