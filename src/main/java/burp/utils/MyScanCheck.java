package burp.utils;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.ScanCheck;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static burp.api.montoya.scanner.ConsolidationAction.KEEP_BOTH;
import static burp.api.montoya.scanner.ConsolidationAction.KEEP_EXISTING;

import static burp.application.Actuator.checkActuator;
import static burp.application.Bucket.CheckBucket;
import static burp.application.Druid.CheckDruid;
import static burp.application.SOAP.checkSOAP;
import static burp.application.Swagger.checkSwagger;

public class MyScanCheck implements ScanCheck {
    private final MontoyaApi api;
    private static final Set<String> scannedPaths = new HashSet<>();

    public MyScanCheck(MontoyaApi api)
    {
        this.api = api;
    }
    @Override
    public AuditResult activeAudit(HttpRequestResponse httpRequestResponse, AuditInsertionPoint auditInsertionPoint) {
            return null;
        }

    @Override
    public AuditResult passiveAudit(HttpRequestResponse httpRequestResponse) {
        List<AuditIssue> allIssues = new ArrayList<>();
        allIssues.add(checkActuator(api,scannedPaths,httpRequestResponse));
        allIssues.add(checkSwagger(api,scannedPaths,httpRequestResponse));
        allIssues.add(checkSOAP(api,scannedPaths,httpRequestResponse));
        allIssues.add(CheckBucket(api,scannedPaths,httpRequestResponse));
        allIssues.add(CheckDruid(api,scannedPaths,httpRequestResponse));
        return AuditResult.auditResult(allIssues);
    }

    @Override
    public ConsolidationAction consolidateIssues(AuditIssue auditIssue, AuditIssue auditIssue1) {
        return auditIssue1.name().equals(auditIssue.name()) ? KEEP_EXISTING : KEEP_BOTH;
    }


}
