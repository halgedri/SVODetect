package gui;

import burp.IBurpExtenderCallbacks;
import burp.ITab;
import java.awt.*;

public class UITab implements ITab {


    //private UiComponent uiComponent;
    private final IBurpExtenderCallbacks callbacks;
    private UIMain main;

    public UITab(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.main = new UIMain(callbacks);
        callbacks.customizeUiComponent(main);
        callbacks.addSuiteTab(this);
    }

    @Override
    public String getTabCaption() {
        return "SVODetect";
    }

    @Override
    public Component getUiComponent() {

        return main;
    }

    public UIMain getUiMain() {
        return main;
    }
}
