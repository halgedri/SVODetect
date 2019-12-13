package burp;

import detection.RespDiffs;
import svo_gui.UiComponents;
import java.awt.*;
import java.io.PrintWriter;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class BurpExtender implements IBurpExtender, ITab, IScannerCheck {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private PrintWriter stdout;
    private RespDiffs respDiffs;

    private static final String extensionName = "SVODetect";
    private URL url;

    UiComponents svogui = new UiComponents();

    HashMap <URL, byte[]> baseResponseMap = new HashMap <URL, byte[] >();

    ArrayList <URL> urlList = new ArrayList<URL>();

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {

        this.callbacks = callbacks;
        helpers = callbacks.getHelpers();

        //for the Output of the Extension
        stdout = new PrintWriter(callbacks.getStdout(), true);

        callbacks.setExtensionName(extensionName);

        callbacks.registerScannerCheck(this);

        // Output when you load the Extension into Burp
        //stdout.println("Version 1.0:  SVODetect will help you to find Session Variable Overloading in your Web Application!");

    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {

        byte [] baseResponseInByte = baseRequestResponse.getResponse();
        url = helpers.analyzeRequest(baseRequestResponse).getUrl();
        baseResponseMap.put(url, baseResponseInByte);
        urlList.add(url);

        return null;
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse scanRequestResponse, IScannerInsertionPoint iScannerInsertionPoint) { //NullPointerException

        String baseVal = iScannerInsertionPoint.getBaseValue();
        String insertionPointName = iScannerInsertionPoint.getInsertionPointName();

        HashMap <URL, byte[]> scanResponseMap = new HashMap <URL, byte[]>();


        //2. insert something in Insertion Point Base --> ins_param_body
        //3. send new Request/ save the Response

        switch (iScannerInsertionPoint.getInsertionPointType()){
            case IScannerInsertionPoint.INS_PARAM_BODY:
                url = helpers.analyzeRequest(scanRequestResponse).getUrl(); //gets the URL where the Insertion Point is

                for (URL url : urlList){
                    byte[] scanRequest = helpers.buildHttpRequest(url);
                    IHttpRequestResponse scanReqRep = callbacks.makeHttpRequest(scanRequestResponse.getHttpService(), scanRequest);
                    byte[] scanResponse = scanReqRep.getResponse();
                    if(url != null && scanResponse != null){
                        scanResponseMap.put(url, scanResponse );
                    }


                }

                //4. compare the baseResponse and the new Response --> if something changed set true

                //respDiffs.areEqualKeyValues(scanResponseMap, baseResponseMap);
                Map < URL, Boolean> responseDiffMap = new HashMap<URL, Boolean>();

                if(scanResponseMap != null && baseResponseMap != null){
                try{
                    responseDiffMap = null;
                            //respDiffs.areEqualKeyValues(scanResponseMap, baseResponseMap); //NullPointerException

                }
                catch (Exception e){
                    stdout.println("Something went wrong");
                }

                }


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

    @Override
    public String getTabCaption() {
        return extensionName;
    }

    //Content of the Tab, when its displayed
    @Override
    public Component getUiComponent() {
        return null;
    }

}