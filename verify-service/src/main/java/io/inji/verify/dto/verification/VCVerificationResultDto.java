package io.inji.verify.dto.verification;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import java.util.List;
import java.util.Map;

@Getter
@Setter
@NoArgsConstructor
public class VCVerificationResultDto {
    private boolean allChecksSuccessful;
    private SchemaAndSignatureCheckDto schemaAndSignatureCheck;
    private ExpiryCheckDto expiryCheck;
    private List<StatusCheckDto> statusCheck;
    private Map<String, Object> claims;
    private IssuerAuthorizationCheckDto issuerAuthorizationCheck;

    public VCVerificationResultDto(boolean allChecksSuccessful,
                                   SchemaAndSignatureCheckDto schemaAndSignatureCheck,
                                   ExpiryCheckDto expiryCheck,
                                   List<StatusCheckDto> statusCheck,
                                   Map<String, Object> claims) {
        this(allChecksSuccessful, schemaAndSignatureCheck, expiryCheck, statusCheck, claims, null);
    }

    public VCVerificationResultDto(boolean allChecksSuccessful,
                                   SchemaAndSignatureCheckDto schemaAndSignatureCheck,
                                   ExpiryCheckDto expiryCheck,
                                   List<StatusCheckDto> statusCheck,
                                   Map<String, Object> claims,
                                   IssuerAuthorizationCheckDto issuerAuthorizationCheck) {
        this.allChecksSuccessful = allChecksSuccessful;
        this.schemaAndSignatureCheck = schemaAndSignatureCheck;
        this.expiryCheck = expiryCheck;
        this.statusCheck = statusCheck;
        this.claims = claims;
        this.issuerAuthorizationCheck = issuerAuthorizationCheck;
    }
}
