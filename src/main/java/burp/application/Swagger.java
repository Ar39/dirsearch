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

import static burp.utils.CommonUtils.getParentPaths;
import static burp.utils.CommonUtils.reportIssue;

public class Swagger {
    public static  AuditIssue checkSwagger(MontoyaApi api, Set<String> scannedPaths, HttpRequestResponse requestResponse){
        final String issueTypes = "Swagger";
        List<String> payloads = new ArrayList<>(Arrays.asList("api-docs", "swagger","swagger-ui.html","swagger-resources"));
        RequestOptions REQUEST_OPTIONS = RequestOptions.requestOptions().withRedirectionMode(RedirectionMode.ALWAYS).withResponseTimeout(10000);
        List<String> paths = getParentPaths(requestResponse);
        for (String path : paths) {
            for (String payload : payloads) {
                String fullPath = path + payload;
                if (scannedPaths.contains(fullPath)) {
                    continue; // 跳过已扫描路径
                }
                scannedPaths.add(fullPath); // 记录新路径
                HttpRequest checkRequest = requestResponse.request().withPath(fullPath);
                //设置请求方式此处跟随跳转
                HttpRequestResponse checkRequestResponse = api.http().sendRequest(checkRequest,REQUEST_OPTIONS);
                if (checkRequestResponse.response().statusCode() == 200) {
                    Boolean flag = checkResponse(checkRequestResponse);
                    if (flag) {
                        AuditIssue issue = reportIssue(issueTypes,checkRequestResponse, payload);
                        return issue;
                    }
                }

            }
        }
        return null;
    }
        public static Boolean checkResponse(HttpRequestResponse httpRequestResponse) {
            String resp = httpRequestResponse.response().body().toString();
            try{
                    if (resp.contains("\"swagger\":\"2.0\"")
                        || resp.contains("\"openapi\":\"3.0\"")
                        || resp.contains("<div id=\"swagger-ui\">")
                        || resp.contains("swagger-ui-container")
                        || resp.contains("swagger-ui.css")
                        || resp.contains("swagger-ui")
                        || resp.contains("Swagger UI")) {
                        return true;
                }
            }catch (Exception e){
                return false;
            }
            return false;
        }

}
