package io.inji.verify.dto.verification;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class IssuerAuthorizationCheckDto {
    private boolean checked;
    private Boolean authorised;
    private String issuerId;
    private String credentialType;
    private String reason;
    private String evaluatedAt;
    private String error;
}
