package burp.application;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.RedirectionMode;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.issues.AuditIssue;

import java.util.List;
import java.util.Set;

import static burp.utils.CommonUtils.getParentPaths;
import static burp.utils.CommonUtils.reportIssue;

public class Druid {
    public static AuditIssue CheckDruid(MontoyaApi api ,Set<String>scannedPaths, HttpRequestResponse httpRequestResponse){
        String payload = "/druid/index.html";
        RequestOptions REQUEST_OPTIONS = RequestOptions.requestOptions().withRedirectionMode(RedirectionMode.ALWAYS).withResponseTimeout(10000);
        List<String> paths = getParentPaths(httpRequestResponse);
        for (String url : paths) {
            String fullPath = url + payload;
            if (scannedPaths.contains(fullPath)) {
                continue; // 跳过已扫描路径
            }
            scannedPaths.add(fullPath); // 记录新路径
            HttpRequest checkRequest = httpRequestResponse.request().withPath(fullPath);
            checkRequest = checkRequest.withMethod("GET");
            HttpRequestResponse checkRequestResponse = api.http().sendRequest(checkRequest,REQUEST_OPTIONS);
            if (checkRequestResponse.response().statusCode() == 200) {
                Boolean flag = checkResponse(checkRequestResponse);
                if (flag) {
                    //可视化后序实现
                    AuditIssue issue = reportIssue("Druid",checkRequestResponse, payload);
                    return issue;
                }
            }
        }
        return null;
    }

    public static Boolean checkResponse(HttpRequestResponse httpRequestResponse) {
        String resp = httpRequestResponse.response().body().toString();
        String xPowerBy = httpRequestResponse.response().headerValue("X-Powered-By");
        try{
            if (resp.contains("DruidVersion")
                    || resp.contains("Druid Stat Index")
                    || resp.contains("com.alibaba.druid")
                    || resp.contains("DruidDrivers")
                    || xPowerBy.contains("Druid")) {
                return true;
            }
        }catch (Exception e){
            return false;
        }
        return false;
    }

}
