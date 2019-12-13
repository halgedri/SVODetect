package scanner;

import burp.IHttpRequestResponse;
import burp.IScannerInsertionPoint;

import java.util.ArrayList;

public class Headers {


    //Load Headers

    ArrayList <String> baseResponseArrayList = new ArrayList<String>();
    ArrayList <String> insertionPointList = new ArrayList<String>();


    public ArrayList baseResponseArray(String baseResponse){

        baseResponseArrayList.add(baseResponse);

        return baseResponseArrayList;

    }

    public ArrayList modifiedRequest (){



        return null;

    }
    //get Insert into website Request
    // send Request
    //load other sites of the Website again
    // compare responses





    public ArrayList temp4InsertionPoints (String requestResponse, IScannerInsertionPoint insertionPoint){

        return null;

    }



    public IHttpRequestResponse response_original;

    public IHttpRequestResponse response_reloaded;

    public IHttpRequestResponse getResponse_original() {

     //   IRequestInfo.getHeaders(response_original);
        // Response_original Array mit z.B. zwei Werten [content_length, status_code]


        return response_original;
    }

    public IHttpRequestResponse getResponse_reloaded() {


        return response_reloaded;
    }

    public void findDifferencesHeaders(){

        //Headers are a Sequence of Bytes

        // Headers beinhalten nur Information zu content-length und status code



    }



}
