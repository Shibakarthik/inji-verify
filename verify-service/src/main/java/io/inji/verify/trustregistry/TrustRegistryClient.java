package io.inji.verify.trustregistry;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.http.client.SimpleClientHttpRequestFactory;

@Slf4j
@Component
public class TrustRegistryClient {

    private final RestTemplate restTemplate;
    private final String baseUrl;

    public TrustRegistryClient(
            @Value("${inji.verify.trust-registry.base-url:}") String baseUrl,
            @Value("${inji.verify.trust-registry.connect-timeout:3000}") int connectTimeout,
            @Value("${inji.verify.trust-registry.read-timeout:3000}") int readTimeout) {
        this.baseUrl = baseUrl == null ? null : baseUrl.replaceAll("/+$", "");
        SimpleClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory();
        requestFactory.setConnectTimeout(connectTimeout);
        requestFactory.setReadTimeout(readTimeout);
        this.restTemplate = new RestTemplate(requestFactory);
    }

    public TrustRegistryResponseDto checkAuthorization(String issuerId, String credentialType) {
        if (baseUrl == null || baseUrl.isBlank()) {
            throw new IllegalStateException("Trust Registry base URL is not configured");
        }

        String url = UriComponentsBuilder.fromUriString(baseUrl)
                .path("/v1/authorizations/check")
                .queryParam("issuerId", issuerId)
                .queryParam("credentialType", credentialType)
                .build()
                .encode()
                .toUriString();

        try {
            return restTemplate.getForObject(url, TrustRegistryResponseDto.class);
        } catch (RestClientException ex) {
            log.warn("Trust Registry authorization request failed: {}", ex.getMessage());
            throw ex;
        }
    }
}
