package burp.application;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.RedirectionMode;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.audit.issues.AuditIssue;


import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

import static burp.utils.CommonUtils.reportIssue;
import static burp.utils.CommonUtils.getParentPaths;

public class SOAP {
    public static AuditIssue checkSOAP(MontoyaApi api, Set<String> scannedPaths, HttpRequestResponse httpRequestResponse) {
        List<String> payloads = new ArrayList<>(Arrays.asList("service", "services","webservice","webservices"));
        RequestOptions REQUEST_OPTIONS = RequestOptions.requestOptions().withRedirectionMode(RedirectionMode.ALWAYS).withResponseTimeout(10000);
        List<String> paths = getParentPaths(httpRequestResponse);
        for (String url : paths) {
            for (String payload : payloads) {
                String fullPath = url + payload;
                if (scannedPaths.contains(fullPath)) {
                    continue; // 跳过已扫描路径
                }
                scannedPaths.add(fullPath); // 记录新路径
                HttpRequest checkRequest = httpRequestResponse.request().withPath(fullPath);
                //设置请求方式此处跟随跳转
                AuditIssue issue = getAuditResult(api, REQUEST_OPTIONS, checkRequest,payload);
                if (issue != null) return issue;
            }
        }
        // 需要实现?wsdl
        String withoutQueryPath = httpRequestResponse.request().pathWithoutQuery();
        String WSDLPath = withoutQueryPath + "?wsdl";
        HttpRequest checkRequest = httpRequestResponse.request().withPath(WSDLPath);
        AuditIssue issue = getAuditResult(api, REQUEST_OPTIONS, checkRequest, "wsdl");
        if (issue != null) return issue;
        return null;
    }

    private static AuditIssue getAuditResult(MontoyaApi api, RequestOptions REQUEST_OPTIONS, HttpRequest checkRequest, String payload) {
        HttpRequestResponse checkRequestResponse = api.http().sendRequest(checkRequest,REQUEST_OPTIONS);
        if (checkRequestResponse.response().statusCode() == 200) {
            Boolean flag = checkResponse(checkRequestResponse);
            if (flag) {
                //可视化后序实现
                AuditIssue issue = reportIssue("SOAP",checkRequestResponse, payload);
                return issue;
            }
        }
        return null;
    }


    public static Boolean checkResponse(HttpRequestResponse httpRequestResponse) {
        String resp = httpRequestResponse.response().body().toString();
        try{
            if (isXmlContent(httpRequestResponse)) {
                if (containsSoapIndicator(httpRequestResponse)) {
                    return true;
                }
            }
        }catch (Exception e){
            return false;
        }
        return false;
    }

    private static boolean isXmlContent(HttpRequestResponse response) {
        String contentType = response.response().headerValue("Content-Type");
        return contentType != null &&
                (contentType.contains("text/xml") ||
                        contentType.contains("application/soap+xml"));
    }

    private static boolean containsSoapIndicator(HttpRequestResponse response) {
        String body = response.response().body().toString();
        return body.contains("soap:Envelope") ||
                body.contains("soap-env:Envelope") ||
                body.contains("<wsdl:definitions");
    }
}
