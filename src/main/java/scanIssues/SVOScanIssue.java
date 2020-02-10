package scanIssues;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;


public class SVOScanIssue extends CustomScanIssue {

    private static String detail1 = "For the following insertion point <b>$INSERTIONPOINTURL</b>  a Session Variable Overloading Issue has been reported.";
    private static String detail2 = "First the Insertion Point at <b>$INSERTIONPOINTURL </b>  was filled";
    private static String detail3 = " with the following parameters <b>$INSERTIONPOINTPARAMLIST </b> ";
    private static String detail4 = "Then in the same session <b>$SCANURL </b> has been called. Session variables have been overloaded. Please check the following case manually and \n" +
            "look at the remediation instructions.";

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
                detail1.replace("$INSERTIONPOINTURL", insertionPointUrl)+
                        detail2.replace("$INSERTIONPOINTURL", insertionPointUrl)+
                        detail3.replace("$INSERTIONPOINTPARAMLIST", insertionPointParameters)+
                        detail4.replace("$SCANURL", helpers.analyzeRequest(scanRequestResponse).getUrl().toString()),
                "Firm"
        );
    }
}

