package detection;

import burp.IHttpRequestResponse;
import burp.ISessionHandlingAction;

public class SessionHandling implements ISessionHandlingAction {

    @Override
    public String getActionName() {
        return "CookieHandlingAction";
    }

    @Override
    public void performAction(IHttpRequestResponse iHttpRequestResponse, IHttpRequestResponse[] iHttpRequestResponses) {




    }
}
