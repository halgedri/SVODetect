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

    //TODO Change Method Name; 500 internal server error
    public void getResponseDiff(IHttpRequestResponse insertionPointRequestResponse, IScannerInsertionPoint iScannerInsertionPoint) {

        URL insertionPointRequestResponseUrl = helpers.analyzeRequest(insertionPointRequestResponse).getUrl();
        IHttpService iHttpService = insertionPointRequestResponse.getHttpService();
        IResponseInfo insertionPointResponseInfo = helpers.analyzeResponse(insertionPointRequestResponse.getResponse());
        List<ICookie> insertionPointResponseCookie = insertionPointResponseInfo.getCookies();
        IParameter cookieResponseParameter = null;

        Map<URL, byte[]> scanResponseMap = new HashMap<URL, byte[]>();

        for (ICookie iCookie : insertionPointResponseCookie) {
            String cookieName = iCookie.getName();
            String cookieValue = iCookie.getValue();
            cookieResponseParameter = helpers.buildParameter(cookieName, cookieValue, (byte) 0x2);
        }

        if (insertionPointResponseCookie.size() == 0) {
            // hole das Cookie vom Request und builde ein Parameter damit

            List<IParameter> requestParamter = helpers.analyzeRequest(insertionPointRequestResponse).getParameters();

        }

        //Set<URL> baseResponseMapUrlKeySet = baseResponseMap.keySet();

        stdout.println("Url from the InsertionPoint:  " + insertionPointRequestResponseUrl);

        for (URL url : baseResponseMap.keySet()) {

            byte[] baseResponse = baseResponseMap.get(url);
            IHttpRequestResponse scanRequestResponse;

            IResponseInfo baseResponseInfo = helpers.analyzeResponse(baseResponse);
            List<String> baseResponseInfoHeaders = baseResponseInfo.getHeaders();

            String urlTest = url.toString();
            // helpers.buildHttpMessage(); mit baseRequestInfoHeader, Request holen für eine bestimmte URL

            byte[] scanPayload = helpers.buildHttpRequest(url);

            if (cookieResponseParameter != null) {
                byte[] scanPayload2 = helpers.addParameter(scanPayload, cookieResponseParameter);
                scanRequestResponse = callbacks.makeHttpRequest(iHttpService, scanPayload2);
            } else {
                //nimm das Cookie vom Request

                scanRequestResponse = callbacks.makeHttpRequest(iHttpService, scanPayload);
            }

            byte[] scanResponse = scanRequestResponse.getResponse();

            IResponseInfo scanResponseInfo = helpers.analyzeResponse(scanResponse);

            //List <String> scanRequestHeader = helpers.analyzeRequest(scanRequestResponse).getHeaders();

            IResponseVariations iResponseVariations = helpers.analyzeResponseVariations(baseResponse, scanResponse);

            List<String> variantAttributes = iResponseVariations.getInvariantAttributes();

            stdout.println(url);
            stdout.println(variantAttributes);
            for (String attribute : variantAttributes) {
                int baseResponseAttribute = iResponseVariations.getAttributeValue(attribute, 0);
                int scanResponseAttribute = iResponseVariations.getAttributeValue(attribute, 0);

                stdout.println("baseResponseAttribute: " + baseResponseAttribute);
                stdout.println("scanResponseAttribute: " + scanResponseAttribute);

            }


        }

    }

}