package loadHeaders;

import burp.IHttpRequestResponse;
import burp.IRequestInfo;

public class headers {

    public IHttpRequestResponse response_original;

    byte response[];
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

    public boolean isHeaderDifferent(IHttpRequestResponse response_original, IHttpRequestResponse response_reloaded) {
        //load headers into array

        return true;
    }

}
