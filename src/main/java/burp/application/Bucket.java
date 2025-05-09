package burp.application;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.RedirectionMode;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.utilities.json.JsonNode;
import burp.api.montoya.utilities.json.JsonObjectNode;

import java.util.List;
import java.util.Set;

import static burp.utils.CommonUtils.getParentPaths;
import static burp.utils.CommonUtils.reportIssue;

public class Bucket {
    public static AuditIssue CheckBucket(MontoyaApi api, Set<String> scannedPaths, HttpRequestResponse httpRequestResponse) {
        RequestOptions REQUEST_OPTIONS = RequestOptions.requestOptions().withRedirectionMode(RedirectionMode.ALWAYS).withResponseTimeout(10000);
        String fileExtension = httpRequestResponse.request().fileExtension();
        if(fileExtension.equals("png") || fileExtension.equals("jpg") || fileExtension.equals("jpeg") || fileExtension.equals("gif") || fileExtension.equals("bmp")) {
            List<String> paths = getParentPaths(httpRequestResponse);
            for(String path : paths) {
                if (scannedPaths.contains(path)) {
                    continue; // 跳过已扫描路径
                }
                scannedPaths.add(path); // 记录新路径
                HttpRequest checkRequest = httpRequestResponse.request().withPath(path);
                checkRequest = checkRequest.withMethod("GET");
                HttpRequestResponse checkRequestResponse = api.http().sendRequest(checkRequest, REQUEST_OPTIONS);
                if(checkRequestResponse.response().statusCode() == 200) {
                   boolean flag = checkResponse(checkRequestResponse);
                   if(flag) {
                       AuditIssue issue = reportIssue("Object Query",checkRequestResponse, "/");
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
            if (httpRequestResponse.response().headerValue("Content-Type").contains("text/xml")) {
                if (resp.contains("<ListBucketResult>")) {
                    return true;
                }
            }
        }catch (Exception e){
            return false;
        }
        return false;
    }
}
