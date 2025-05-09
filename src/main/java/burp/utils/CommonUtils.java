package burp.utils;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

import java.util.ArrayList;
import java.util.List;

import static burp.api.montoya.scanner.AuditResult.auditResult;
import static burp.api.montoya.scanner.audit.issues.AuditIssue.auditIssue;


public class CommonUtils {

    /**
     * 获取URL中的第一个路径
     * @return String
     */
    public static String getUrlWithPath(HttpRequestResponse  httpRequestResponse){
        String rootPath = getUrlRootPath(httpRequestResponse);

        try {
            String tmpUrl = getUrlWithoutFilename(httpRequestResponse);
            String path = tmpUrl.replaceAll(rootPath, "");
            while (path.startsWith("/")) {
                path = path.substring(1);
            }
            if (path.isEmpty()) {
                return rootPath;
            }else {
                return rootPath + "/" + path.substring(0, path.indexOf("/"));
            }
        }catch (Exception e){
            return rootPath;
        }
    }

    /**
     * 获取host
     * @param httpRequestResponse
     * @return String
     */
    public static String getUrlRootPath(HttpRequestResponse httpRequestResponse){
        String url = httpRequestResponse.request().url();
        return url.substring(0, url.lastIndexOf('/'));
    }


    /**
     * 获取URL中不包含文件的路径
     * @param httpRequestResponse
     * @return
     */
    public static String getUrlWithoutFilename(HttpRequestResponse httpRequestResponse) {
        String urlRootPath = getUrlRootPath(httpRequestResponse);
        String path = httpRequestResponse.request().path();

        if (path.length() == 0) {
            path = "/";
        }

        if (httpRequestResponse.request().path().endsWith("/?format=openapi")) { //对django swagger做单独处理
            return urlRootPath + httpRequestResponse.request().path();
        }

        if (path.endsWith("/")) {
            return urlRootPath + path;
        } else {
            return urlRootPath + path.substring(0, path.lastIndexOf("/") + 1);
        }
    }

    public static List<String> getParentPaths(HttpRequestResponse requestResponse) {

        String path = requestResponse.request().pathWithoutQuery();
        List<String> parentPaths = new ArrayList<>();
        if (path == null || path.isEmpty()) {
            return parentPaths;
        }

        // 标准化路径：去除末尾的冗余斜杠（非必需步骤）
        String normalizedPath = path.endsWith("/") ? path.substring(0, path.length() - 1) : path;

        // 分割路径段
        String[] segments = normalizedPath.split("/");

        // 逐级生成父路径
        StringBuilder currentPath = new StringBuilder();
        for (int i = 0; i < segments.length; i++) {
            if (segments[i].isEmpty()) continue; // 跳过空字符串（如根路径）
            currentPath.append("/").append(segments[i]);
            if (i < segments.length - 1) { // 跳过最后一个段（"add"）
                parentPaths.add(currentPath.toString() + "/");
            }
        }
        parentPaths.add("/"); // 添加根路径

        return parentPaths;
    }

    public static AuditIssue reportIssue(String name,HttpRequestResponse checkRequest, String payload) {
        AuditIssue auditIssue =
                auditIssue(
                        "vulnerabilities " + name,
                        "find vulnerabilities: " + payload,
                        null,
                        checkRequest.request().url(),
                        AuditIssueSeverity.HIGH,
                        AuditIssueConfidence.CERTAIN,
                        null,
                        null,
                        AuditIssueSeverity.HIGH,
                        checkRequest

        );
        return auditIssue;
    }

}

