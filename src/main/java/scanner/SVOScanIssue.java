package scanner;

import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IScanIssue;

import java.net.URL;

public class SVOScanIssue implements IScanIssue {

    private String name, severity, confidence, detail;
    private IHttpService httpService;
    private URL url;
    private IHttpRequestResponse[] httpMessages;



    public void CustomSVOScanIssue(String name, IHttpService httpService, URL url, IHttpRequestResponse[] httpMessages, String severity, String confidence, String detail) {

        this.name = name;
        this.httpService = httpService;
        this.url = url;
        this.httpMessages = httpMessages;
        this.severity = severity;
        this.confidence = confidence;
        this.detail = detail;

    }

    @Override
    public URL getUrl(){
        return url;
    }

    @Override
    public String getIssueName(){
        return name;
    }

    @Override
    public int getIssueType(){
        return 0;
    }

    @Override
    public String getSeverity(){
        return severity;
    }

    @Override
    public String getConfidence(){
        return confidence;
    }

    @Override
    public String getIssueBackground(){
        return "Session Variable Overloading Text -- SHOULD BE WRITTEN!";

    }

    @Override
    public String getRemediationBackground(){
        return "Another Text, that has to be written!";
    }

    @Override
    public String getIssueDetail(){
        return null;
    }

    @Override
    public String getRemediationDetail(){
        return null;
    }

    @Override
    public IHttpRequestResponse[] getHttpMessages(){
        return httpMessages;
    }

    @Override
    public IHttpService getHttpService(){
        return httpService;
    }

}
