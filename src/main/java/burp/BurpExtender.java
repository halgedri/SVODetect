package burp;

import gui.UITab;
import scanIssues.SVOScanIssue;

import java.io.PrintWriter;
import java.net.URL;
import java.util.*;
import java.util.List;


public class BurpExtender implements IBurpExtender, IScannerCheck {

    private IBurpExtenderCallbacks callbacks;
    public IExtensionHelpers helpers;
    private PrintWriter stdout;
    private UITab uiTab;

    private static final String extensionName = "SVODetect";

    private List<IScanIssue> issues;
    private RelevantInfo relevantInfo = new RelevantInfo();
    public List<String> importantAttributesList;
    public List<int[]> responseTokenHighlights;
    private HashMap<URL, byte[]> baseResponseMap = new HashMap<URL, byte[]>();

    private IScanIssue oldIssue = null;

    int counterBeginning = 0;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {

        this.callbacks = callbacks;
        helpers = callbacks.getHelpers();

        stdout = new PrintWriter(callbacks.getStdout(), true);

        callbacks.setExtensionName(extensionName);

        callbacks.registerScannerCheck(this);

        uiTab = new UITab(callbacks);

        importantAttributesList = relevantInfo.getImportantAttributesList();


        stdout.println(" ____________________________________________________ ");
        stdout.println("|                                                    |");
        stdout.println("|                                                    |");
        stdout.println("|SVODetect has successfully been registered to Burp  |");
        stdout.println("|                                                    |");
        stdout.println("|____________________________________________________|");
    }


    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {

        byte[] baseRequest = baseRequestResponse.getRequest();

        String protocol = baseRequestResponse.getHttpService().getProtocol();
        String host = baseRequestResponse.getHttpService().getHost();
        int port = baseRequestResponse.getHttpService().getPort();

        String baseRequestHost = protocol + "://" + host + ":" + port;

        IHttpRequestResponse[] siteMap = callbacks.getSiteMap(baseRequestHost);

        for (IHttpRequestResponse siteMapReqRep : siteMap) {

            URL siteMapUrl = helpers.analyzeRequest(siteMapReqRep).getUrl();

            byte[] basePayload = helpers.buildHttpRequest(siteMapUrl);
            IHttpRequestResponse baseResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), basePayload);

            byte[] baseResponseCheck = baseResponse.getResponse();

            baseResponseMap.put(siteMapUrl, baseResponseCheck);

        }
        return null;
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse iHttpRequestResponse, IScannerInsertionPoint iScannerInsertionPoint) {
        issues = new ArrayList<>();

        switch (iScannerInsertionPoint.getInsertionPointType()) {
            case IScannerInsertionPoint.INS_PARAM_BODY:
                getScanResponse(iHttpRequestResponse);
                if (issues.size() > 0) {
                    return issues;
                } else {
                    return null;
                }

            default:
                return null;
        }
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        if (existingIssue.getIssueDetail() == newIssue.getIssueDetail()) {
            return 1;
        } else {
            return 0;
        }
    }

    public void getScanResponse(IHttpRequestResponse insertionPointRequestResponse) {

        String insertionPointParameterList = "";
        String parameterValueAndName, insertionPointUrlAsString, parameterValue, parameterName, cookieName, cookieValue;
        IHttpService iHttpService;
        IHttpRequestResponse scanRequestResponse;
        IResponseInfo insertionPointResponseInfo, scanResponseInfo;
        IScanIssue issue;
        IParameter cookieResponseParameter = null;
        byte[] scanPayload, scanPayloadWithCookie, scanResponse, baseResponse;
        List<IParameter> newRequestParameter, parametersInsertionPoint;
        List<ICookie> insertionPointResponseCookieList;
        Set<URL> baseResponseMapUrlKeySet;

        insertionPointUrlAsString = helpers.analyzeRequest(insertionPointRequestResponse).getUrl().toString();
        iHttpService = insertionPointRequestResponse.getHttpService();
        parametersInsertionPoint = helpers.analyzeRequest(insertionPointRequestResponse).getParameters();
        baseResponseMapUrlKeySet = baseResponseMap.keySet();

        //get all InsertionPointParameters for the Issue
        byte[] insertionPointRequest = insertionPointRequestResponse.getRequest();
        byte[] newInsertionPointRequest = new byte[0];

        for (IParameter iParameter : parametersInsertionPoint) {
            byte parameterType = iParameter.getType();
            if (parameterType == (byte) 0x2) {
                newInsertionPointRequest = helpers.removeParameter(insertionPointRequest, iParameter);
            }
            parameterValueAndName = insertionPointParameterList + iParameter.getName() + ": " + iParameter.getValue() + " , ";
            insertionPointParameterList = parameterValueAndName;
        }

        for (URL url : baseResponseMapUrlKeySet) {

            IHttpRequestResponse insertionPointHttpRequestResponse = callbacks.makeHttpRequest(iHttpService, newInsertionPointRequest);
            insertionPointResponseInfo = helpers.analyzeResponse(insertionPointHttpRequestResponse.getResponse());
            insertionPointResponseCookieList = insertionPointResponseInfo.getCookies();
            newRequestParameter = helpers.analyzeRequest(insertionPointHttpRequestResponse).getParameters();


            if (!(insertionPointResponseCookieList.isEmpty())) {
                for (ICookie iCookie : insertionPointResponseCookieList) {
                    cookieName = iCookie.getName();
                    cookieValue = iCookie.getValue();
                    cookieResponseParameter = helpers.buildParameter(cookieName, cookieValue, (byte) 0x2);
                }
            } else {
                for (IParameter iParameter : newRequestParameter) {
                    Byte parameterType = iParameter.getType();
                    if (parameterType == (byte) 0x2) {
                        parameterValue = iParameter.getValue();
                        parameterName = iParameter.getName();
                        cookieResponseParameter = helpers.buildParameter(parameterName, parameterValue, parameterType);
                        break;
                    }
                }
            }

            baseResponse = baseResponseMap.get(url);

            scanPayload = helpers.buildHttpRequest(url);
            scanPayloadWithCookie = helpers.addParameter(scanPayload, cookieResponseParameter);

            scanRequestResponse = callbacks.makeHttpRequest(iHttpService, scanPayloadWithCookie);

            scanResponse = scanRequestResponse.getResponse();

            short scanResponseStatusCode = helpers.analyzeResponse(scanResponse).getStatusCode();

            if (scanResponseStatusCode == 404) {
            } else if (scanResponseStatusCode == 500) {
                stdout.println("SERVER ERROR! Check your Application and try a new Scan");
                break;
            } else {
                issue = analyseResponseDifferences(baseResponse, scanRequestResponse, insertionPointUrlAsString, insertionPointParameterList);
                if (issue != null) {
                    issues.add(issue);
                }
            }
        }
    }


    public IScanIssue analyseResponseDifferences(byte[] baseResponse, IHttpRequestResponse scanRequestResponse, String insertionPointUrl, String insertionPointParameters) {


        IScanIssue issue;
        byte[] scanResponse;
        IResponseVariations iResponseVariations;
        List<String> variantAttributesList;
        int variantAttributesCounter;

        scanResponse = scanRequestResponse.getResponse();
        iResponseVariations = helpers.analyzeResponseVariations(baseResponse, scanResponse);
        variantAttributesList = iResponseVariations.getVariantAttributes();
        variantAttributesCounter = 0;

        if (variantAttributesList.size() > 0) {
            for (String variantAttribute : variantAttributesList) {
                if (importantAttributesList.contains(variantAttribute)) {
                    variantAttributesCounter++;
                }
            }
        }

        if (variantAttributesCounter >= 2) {
            issue = new SVOScanIssue(scanRequestResponse, insertionPointUrl, insertionPointParameters, helpers, callbacks);
            return issue;
        }
         else {
            return null;
        }
    }
}