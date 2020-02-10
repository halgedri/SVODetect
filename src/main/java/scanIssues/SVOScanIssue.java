package scanner;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;


public class SVOScanIssue extends CustomScanIssue {

    private static String detail1 = "Hier sollte die URL des InsertionPoints stehen <b>$INSERTIONPOINTURL</b> something else";
    private static String detail2 = "Hier sollten die Parameter des InsertionPoints stehen <b>$INSERTIONPOINTPARAMLIST </b> something else";
    private static String detail3 = "Hier npchmal die InsertionPointURL <b>$INSERTIONPOINTURL </b> something else";
    private static String detail4 = "und hier die sich unterscheidende vom Scan und Base Request <b>$SCANURL </b> something else";

    private static String remediation = "The Source Code should be reviewed. The vulnearbility arsises due to implementation flaws. Overlook the Source Code and check for premature session. <br>"
          +  "Otherwise there is a chance this Vulnerability leads amongst others to: <br>1. Authentication Bypassing <br>"
         + "2. User Impersonation <br> 3. Privilege Escalation <br> 4. Flow Enforcement Bypass <br> 5. it can be used to execute traditional Attacks as Injections";




    public SVOScanIssue(IHttpRequestResponse scanRequestResponse, String insertionPointUrl, String insertionPointParameters, IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks) {
        super(
                scanRequestResponse.getHttpService(),
                new IHttpRequestResponse[] {callbacks.applyMarkers(scanRequestResponse,null,null)},
                helpers.analyzeRequest(scanRequestResponse).getUrl(),
                "Session Variable Overloading",
                0x08000000,
                "High",
                remediation,
                detail1.replace("$INSERTIONPOINTURL", insertionPointUrl)+  detail2.replace("$INSERTIONPOINTPARAMLIST", insertionPointParameters)+
                        detail3.replace("$INSERTIONPOINTURL", insertionPointUrl)+
                        detail4.replace("$SCANURL", helpers.analyzeRequest(scanRequestResponse).getUrl().toString()),
                "Firm"
        );
    }
}

