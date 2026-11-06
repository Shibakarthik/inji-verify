package io.inji.verify.trustregistry;

import io.inji.verify.dto.verification.IssuerAuthorizationCheckDto;
import io.mosip.vercred.vcverifier.constants.CredentialFormat;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class TrustRegistryServiceTest {

    private final TrustRegistryClient client = mock(TrustRegistryClient.class);
    private final TrustRegistryService service = new TrustRegistryService(client, true);

    @Test
    void shouldAuthorizeRegisteredIssuerAndCredentialType() {
        String credential = """
                {"issuer":{"id":"did:web:issuer.example"},"type":["VerifiableCredential","FarmerCredential"]}
                """;
        TrustRegistryResponseDto response = new TrustRegistryResponseDto();
        response.setAuthorised(true);
        response.setReason("ISSUER_AUTHORIZED");
        response.setEvaluatedAt("2026-11-06T10:00:00Z");
        when(client.checkAuthorization("did:web:issuer.example", "FarmerCredential")).thenReturn(response);

        IssuerAuthorizationCheckDto result = service.checkIssuerAuthorization(credential, CredentialFormat.LDP_VC);

        assertTrue(result.isChecked());
        assertTrue(result.getAuthorised());
        assertEquals("did:web:issuer.example", result.getIssuerId());
        assertEquals("FarmerCredential", result.getCredentialType());
        assertEquals("ISSUER_AUTHORIZED", result.getReason());
    }

    @Test
    void shouldSupportIssuerAsString() {
        String credential = """
                {"issuer":"did:web:issuer.example","type":"FarmerCredential"}
                """;
        TrustRegistryResponseDto response = new TrustRegistryResponseDto();
        response.setAuthorised(false);
        response.setReason("ISSUER_NOT_FOUND");
        when(client.checkAuthorization("did:web:issuer.example", "FarmerCredential")).thenReturn(response);

        IssuerAuthorizationCheckDto result = service.checkIssuerAuthorization(credential, CredentialFormat.LDP_VC);

        assertFalse(result.getAuthorised());
        assertEquals("ISSUER_NOT_FOUND", result.getReason());
    }

    @Test
    void shouldFailClosedWhenRegistryIsUnavailable() {
        String credential = """
                {"issuer":"did:web:issuer.example","type":["VerifiableCredential","FarmerCredential"]}
                """;
        when(client.checkAuthorization(anyString(), anyString())).thenThrow(new RuntimeException("connection refused"));

        IssuerAuthorizationCheckDto result = service.checkIssuerAuthorization(credential, CredentialFormat.LDP_VC);

        assertTrue(result.isChecked());
        assertFalse(result.getAuthorised());
        assertEquals("REGISTRY_UNAVAILABLE", result.getReason());
    }

    @Test
    void shouldFailClosedWhenCredentialMetadataIsMissing() {
        String credential = """
                {"type":["VerifiableCredential"]}
                """;

        IssuerAuthorizationCheckDto result = service.checkIssuerAuthorization(credential, CredentialFormat.LDP_VC);

        assertTrue(result.isChecked());
        assertFalse(result.getAuthorised());
        assertEquals("CREDENTIAL_METADATA_MISSING", result.getReason());
        verifyNoInteractions(client);
    }

    @Test
    void shouldFailClosedForUnsupportedFormats() {
        IssuerAuthorizationCheckDto result = service.checkIssuerAuthorization("opaque-token", CredentialFormat.VC_SD_JWT);

        assertTrue(result.isChecked());
        assertFalse(result.getAuthorised());
        assertEquals("UNSUPPORTED_CREDENTIAL_FORMAT", result.getReason());
        verifyNoInteractions(client);
    }
}
