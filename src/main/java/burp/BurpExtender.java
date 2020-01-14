package burp;

import detection.SessionHandling;
import gui.UITab;

import java.io.PrintWriter;
import java.net.URL;
import java.util.*;
import java.util.List;


public class BurpExtender implements IBurpExtender, IScannerCheck {

    private IBurpExtenderCallbacks callbacks;
    public IExtensionHelpers helpers;
    private PrintWriter stdout;
    private UITab uiTab;
    public SessionHandling sessionAction = new SessionHandling();

    private static final String extensionName = "SVODetect";
    private URL url;
    private URL urlSiteMap;


    HashMap<URL, byte[]> baseResponseMap = new HashMap<URL, byte[]>();

    ArrayList<URL> urlList = new ArrayList<URL>();
    ArrayList<IHttpRequestResponse> baseRequestSiteMap = new ArrayList<>();

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {

        this.callbacks = callbacks;
        helpers = callbacks.getHelpers();

        stdout = new PrintWriter(callbacks.getStdout(), true);

        callbacks.setExtensionName(extensionName);

        callbacks.registerScannerCheck(this);

        uiTab = new UITab(callbacks);

        //callbacks.registerSessionHandlingAction(sessionAction);
    }


    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {

        byte[] baseRequest = baseRequestResponse.getRequest();

        IHttpRequestResponse[] siteMap = callbacks.getSiteMap("http://127.1.1.1:8080/puzzlemall");

        // For every Item in siteMap a new Request is build
        for (IHttpRequestResponse siteMapReqRep : siteMap) {

            URL siteMapUrl = helpers.analyzeRequest(siteMapReqRep).getUrl();

            byte[] basePayload = helpers.buildHttpRequest(siteMapUrl);
            IHttpRequestResponse baseResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), basePayload);

            byte[] baseResponseCheck = baseResponse.getResponse();

            baseResponseMap.put(siteMapUrl, baseResponseCheck);
        }

        /*
        * To get all Parameters in a Request, with the used Method
        *
        List<IParameter> baseRequestParamList = new ArrayList<>();
        baseRequestParamList = helpers.analyzeRequest(baseRequestResponse).getParameters();
        for (IParameter param : baseRequestParamList) {
            stdout.println(param.getName());
        }

        String baseMethod = helpers.analyzeRequest(baseRequest).getMethod();

        stdout.println("Parameter Liste:  " + baseRequestParamList + "\n");
        stdout.println("Method: " + baseMethod + "\n" + "\n" + "\n" + "\n");

        */
        return null;
    }

    int counter = 0;

    //iScannerInsertionPoint reagiert auf POST
    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse iHttpRequestResponse, IScannerInsertionPoint iScannerInsertionPoint) {

        switch (iScannerInsertionPoint.getInsertionPointType()) {
            case IScannerInsertionPoint.INS_PARAM_BODY:
                getResponseDiff(iHttpRequestResponse, iScannerInsertionPoint);
                break;
            default:
                break;
        }
        return null;
    }


    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        if (existingIssue.getIssueDetail() == newIssue.getIssueDetail()) {
            return 1;
        } else {
            return 0;
        }
    }

    public Map<URL, List> analyzeResponseDiff(HashMap<URL, byte[]> first, HashMap<URL, byte[]> second) {

        Map<URL, List> responseDiffMap = new HashMap<>();

        for (URL url : first.keySet()) {

            List<String> responseVariationsList = new ArrayList<String>();

            byte[] firstBytesResponse = first.get(url);
            byte[] secondBytesResponse = second.get(url);

            responseVariationsList = helpers.analyzeResponseVariations(firstBytesResponse, secondBytesResponse).getVariantAttributes();
            //stdout.println("Response Variations:  " + responseVariationsList);
            /*

            if (firstBytesResponse.length == secondBytesResponse.length) {
                for (int k = 0; k < firstBytesResponse.length; k++) {

                    if (firstBytesResponse[k] == secondBytesResponse[k]) {

                    } else {

                        stdout.println("Here is a Difference ");
                        stdout.println(k);

                        //stdout.println(firstBytesResponse[k] + "       " + secondBytesResponse[k]);
                        //stdout.println(helpers.bytesToString(firstBytesResponse) + " \n  second:     \n   "+ helpers.bytesToString(secondBytesResponse) );

                    }
                }
            }
*/
            /*if (firstBytesResponse.equals(secondBytesResponse)) {
                responseVariationsList.add(("They are Equal"));
            } else {

                responseVariationsList = helpers.analyzeResponseVariations(firstBytesResponse, secondBytesResponse).getVariantAttributes();
            }*/
            responseDiffMap.put(url, responseVariationsList);


        }
        // stdout.println("Response Variant Attributes:  "+responseDiffMap);
        return responseDiffMap;

    }


    public void getResponseDiff(IHttpRequestResponse insertionPointRequestResponse, IScannerInsertionPoint iScannerInsertionPoint) {

        URL insertionPointRequestResponseUrl;
        List<String> insertionPointRequestResponseHeader;
        IHttpService iHttpService;
        IResponseInfo insertionPointResponseInfo;
        List<ICookie> insertionPointResponseCookieList;
        IParameter cookieResponseParameter = null;
        List<IParameter> requestParameter;
        Set<URL> baseResponseMapUrlKeySet;
        Map<URL, byte[]> scanResponseMap = new HashMap<URL, byte[]>();
        IResponseInfo scanResponseInfo;

        insertionPointRequestResponseUrl = helpers.analyzeRequest(insertionPointRequestResponse).getUrl();
        insertionPointRequestResponseHeader = helpers.analyzeRequest(insertionPointRequestResponse).getHeaders();
        insertionPointResponseInfo = helpers.analyzeResponse(insertionPointRequestResponse.getResponse());
        insertionPointResponseCookieList = insertionPointResponseInfo.getCookies();

        iHttpService = insertionPointRequestResponse.getHttpService();
        requestParameter = helpers.analyzeRequest(insertionPointRequestResponse).getParameters();
        baseResponseMapUrlKeySet = baseResponseMap.keySet();


        if (!(insertionPointResponseCookieList.isEmpty())) {
            for (ICookie iCookie : insertionPointResponseCookieList) {
                String cookieName = iCookie.getName();
                String cookieValue = iCookie.getValue();
                cookieResponseParameter = helpers.buildParameter(cookieName, cookieValue, (byte) 0x2);
            }
        } else {
            for (IParameter iParameter : requestParameter) {
                Byte parameterType = iParameter.getType();
                if (parameterType == (byte) 0x2) {
                    String parameterValue = iParameter.getValue();
                    String parameterName = iParameter.getName();
                    cookieResponseParameter = helpers.buildParameter(parameterName, parameterValue, parameterType);
                }
            }
        }

        for (URL url : baseResponseMapUrlKeySet) {

            if (url.toString().equals("http://127.1.1.1:8080/puzzlemall/logout.jsp")
                    || url.toString().equals("http://127.1.1.1:8080/puzzlemall/login.jsp")
                    || url.toString().equals("http://127.1.1.1:8080/puzzlemall/recovery-phase2.jsp")
                    || url.toString().equals("http://127.1.1.1:8080/puzzlemall/register-phase2.jsp")) {
            } else {
                byte[] baseResponse = baseResponseMap.get(url);

                IHttpRequestResponse scanRequestResponse;
                IResponseInfo baseResponseInfo;
                byte[] scanPayload;
                byte[] scanPayloadWithCookie;
                byte[] scanResponse;
                IResponseVariations iResponseVariations;

                baseResponseInfo = helpers.analyzeResponse(baseResponse);

                scanPayload = helpers.buildHttpRequest(url);
                scanPayloadWithCookie = helpers.addParameter(scanPayload, cookieResponseParameter);

                scanRequestResponse = callbacks.makeHttpRequest(iHttpService, scanPayloadWithCookie);
                scanResponse = scanRequestResponse.getResponse();

                scanResponseInfo = helpers.analyzeResponse(scanResponse);

                analyseResponseDifference(baseResponse, scanResponse);


            }
        }
    }

    public Map<URL, List> analyseResponseDifference(byte[] baseResponse, byte[] scanResponse) {
        // je mehr Attribute sich unterscheiden, desto wahrscheinlicher ist, dass die Seite sich verändert hat
        // wie kann man den Login mit usernamen und passwort, also eine legitime Authentifizierung

        IResponseVariations iResponseVariations = helpers.analyzeResponseVariations(baseResponse, scanResponse);

        float variantAttributesCount = iResponseVariations.getVariantAttributes().size();
        float invariantAttributesCount = iResponseVariations.getInvariantAttributes().size();

        float attributesTotal = variantAttributesCount + invariantAttributesCount;

        float variantAttributesPercentage = variantAttributesCount/attributesTotal;
        stdout.println("SVO is " + variantAttributesPercentage + " mostlikely to happen");


        return null;
    }
}