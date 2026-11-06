package io.inji.verify.trustregistry;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class TrustRegistryResponseDto {
    private String issuerId;
    private String credentialType;
    private Boolean authorised;
    private String reason;
    private String evaluatedAt;
    private String apiVersion;
}
