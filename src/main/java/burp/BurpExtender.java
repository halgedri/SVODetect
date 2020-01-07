package burp;

import gui.UITab;

import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.*;
import java.util.List;

public class BurpExtender implements IBurpExtender, IScannerCheck {

    private IBurpExtenderCallbacks callbacks;
    public IExtensionHelpers helpers;
    private PrintWriter stdout;
    private UITab uiTab = new UITab(callbacks);

    private static final String extensionName = "SVODetect";
    private URL url;
    private URL urlSiteMap;

    public IScannerInsertionPointProvider iScannerInsertionPointProvider;


    HashMap<URL, byte[]> baseResponseMap = new HashMap<URL, byte[]>();

    ArrayList<URL> urlList = new ArrayList<URL>();
    ArrayList<IHttpRequestResponse> baseRequestSiteMap = new ArrayList<>();

    int counter = 0;


    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {

        this.callbacks = callbacks;
        helpers = callbacks.getHelpers();

        stdout = new PrintWriter(callbacks.getStdout(), true);

        callbacks.setExtensionName(extensionName);

        callbacks.registerScannerCheck(this);

        callbacks.addSuiteTab(uiTab);

    }


    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {

        //TODO findet den PIRVATE Bereich nicht!!
        // private/mainmenu .. jetzt manuell einfügen und manuell prüfen
        // dann auf Analyse gehen

        List<IParameter> baseRequestParamList = new ArrayList<>();

        byte[] baseRequest = baseRequestResponse.getRequest();

        URL baseRequestURL = helpers.analyzeRequest(baseRequest).getUrl();

        try {
            URL testURL =  new URL ("127.1.1.1:8080/puzzlemall/");
            if ((baseRequestURL.toString()).equals("127.1.1.1:8080/puzzlemall/login.jsp")){
                callbacks.sendToSpider(testURL);
                stdout.println("In the Spider");
            }

        } catch (MalformedURLException e) {
            e.printStackTrace();
        }



        baseRequestParamList = helpers.analyzeRequest(baseRequest).getParameters();

        /*stdout.println("URL:  " + baseRequestURL);
        for (IParameter param : baseRequestParamList) {
            stdout.println(param.getName());
        }

        String baseMethod = helpers.analyzeRequest(baseRequest).getMethod();

        stdout.println("Parameter Liste:  " + baseRequestParamList + "\n");
        stdout.println("Method: " + baseMethod + "\n" + "\n" + "\n" + "\n");
        */


        byte[] basePayload = helpers.buildHttpRequest(baseRequestURL);
        IHttpRequestResponse baseResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), basePayload);

        byte[] baseResponseCheck = baseResponse.getResponse();

        String baseStringURL = baseRequestURL.toString();

        stdout.println(baseRequestURL);

        IHttpRequestResponse[] temp = callbacks.getSiteMap(null);
        stdout.println("LENGTH SITEMAP ZUR URL "+temp.length);

        if (baseStringURL.equals("http://127.1.1.1:8080/puzzlemall/private/mainmenu.jsp")) {
            stdout.println(baseRequestURL);
            stdout.println("BaseResponse:   " + helpers.bytesToString(baseResponseCheck));
        }


        baseResponseMap.put(baseRequestURL, baseResponseCheck);


          stdout.println(baseResponseMap.keySet());

        return null;
    }







    //iScannerInsertionPoint reagiert auf POST
    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse scanRequestResponse, IScannerInsertionPoint iScannerInsertionPoint) {


        URL scanRequestURL = helpers.analyzeRequest(scanRequestResponse).getUrl();

        //stdout.println(scanRequestURL);


/*

        //callbacks.sendToSpider(urlSiteMap);
        //Arrays.stream(callbacks.getSiteMap(urlSiteMap)).forEach(e -> analyseRequestResponse(e));

        URL url2 = helpers.analyzeRequest(scanRequestResponse).getUrl();

        String baseVal = iScannerInsertionPoint.getBaseValue();
        String insertionPointName = iScannerInsertionPoint.getInsertionPointName();

        HashMap<URL, byte[]> scanResponseMap = new HashMap<URL, byte[]>();

        switch (iScannerInsertionPoint.getInsertionPointType()) {
            case IScannerInsertionPoint.INS_PARAM_BODY:

                Map<URL, List> responseDiffMap = new HashMap<URL, List>();

                for (URL url : baseResponseMap.keySet()) {

                    byte[] scanPayload = helpers.buildHttpRequest(url);
                    IHttpRequestResponse scanRequest = callbacks.makeHttpRequest(scanRequestResponse.getHttpService(), scanPayload);

                    byte[] scanResponseInByte = scanRequest.getResponse();
                    // String scanResponse = helpers.bytesToString(scanResponseInByte);


                    String uro = url.toString();

                    stdout.println(url);

                    if (uro.equals("http://127.1.1.1:8080/puzzlemall/private/mainmenu.jsp")) {
                        stdout.println(url);
                        stdout.println("ScanResponse: " + helpers.bytesToString(scanResponseInByte));
                    }
                    scanResponseMap.put(url, scanResponseInByte);

                }


                //responseDiffMap = responseDiff(scanResponseMap, baseResponseMap);
                break;
            default:
                break;
        }*/


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

    public Map<URL, List> responseDiff(HashMap<URL, byte[]> first, HashMap<URL, byte[]> second) {


        //TODO wenn man zunächst Password Recovery Aufruft und danach private/mainmenu sollte es einen Unterschied geben

        Map<URL, List> responseDiffsMap = new HashMap<>();


        for (URL url : first.keySet()) {

            List<String> responseVariationsList = new ArrayList<String>();

            byte[] firstBytesResponse = first.get(url);
            byte[] secondBytesResponse = second.get(url);

            responseVariationsList = helpers.analyzeResponseVariations(firstBytesResponse, secondBytesResponse).getVariantAttributes();


            stdout.println("Response Variations:  " + responseVariationsList);

         /*   if (firstBytesResponse.length == secondBytesResponse.length) {
                for (int k = 0; k < firstBytesResponse.length; k++) {

                    if (firstBytesResponse[k] == secondBytesResponse[k]) {

                    } else {



                        stdout.println("Here is a Difference ");

                        stdout.println(k);

                        stdout.println(firstBytesResponse[k] + "       " + secondBytesResponse[k]);
                    }
                }
            }
/*
            else{
                responseVariationsList.add("They differ");
            }

            if (firstBytesResponse.equals(secondBytesResponse)) {
                responseVariationsList.add(("They are Equal"));
            } else {

                // responseVariationsList = helpers.analyzeResponseVariations(firstBytesResponse, secondBytesResponse).getVariantAttributes();
            }
            responseDiffsMap.put(url, responseVariationsList);*/
        }
        return responseDiffsMap;

    }
}