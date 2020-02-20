package scanIssues;

import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IScanIssue;

import java.net.URL;

public class CustomScanIssue implements IScanIssue {

    private URL scanUrl;
    private String issueName;
    private IHttpService httpService;
    private IHttpRequestResponse[] httpMessages;
    private String severity;
    private String remediation;
    private String detail;
    private int issueType;
    private String confidence;


    public CustomScanIssue( IHttpService httpService,IHttpRequestResponse[] httpMessages, URL scanUrl, String issueName, int issueType,  String severity, String remediation, String detail, String confidence ) {
        this.scanUrl = scanUrl;
        this.issueName = issueName;
        this.issueType = issueType;
        this.httpService = httpService;
        this.httpMessages = httpMessages;
        this.severity  =severity;
        this.remediation = remediation;
        this.detail = detail;
        this.confidence = confidence;
    }


    @Override
    public URL getUrl() {
        return scanUrl;
    }

    @Override
    public String getIssueName() {
        return issueName;
    }

    @Override
    public int getIssueType() {
        return issueType;
    }

    @Override
    public String getSeverity() {
        return severity;
    }

    @Override
    public String getConfidence() {
        return confidence;
    }

    @Override
    public String getIssueBackground() {
        return null;
    }

    @Override
    public String getRemediationBackground() {
        return null;
    }

    @Override
    public String getIssueDetail() {
        return detail;
    }

    @Override
    public String getRemediationDetail() {
        return remediation;
    }

    @Override
    public IHttpRequestResponse[] getHttpMessages() {
        return httpMessages;
    }

    @Override
    public IHttpService getHttpService() {
        return httpService;
        }
}
