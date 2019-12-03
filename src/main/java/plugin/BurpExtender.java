package plugin;

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;

import java.io.OutputStream;
import java.io.PrintWriter;

public class BurpExtender implements IBurpExtender {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;


    private static final String extensionName = "SVODetect";

    // Entry Point of the Extension
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {

        this.callbacks = callbacks;

        //obtain an extension helpers object
        helpers = callbacks.getHelpers();

        // set the Extension Name
        callbacks.setExtensionName(extensionName);


       //for the Output of the Extension
       PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true);

       stdout.println("This is a Test, if SVO Detect works");



    }
}
