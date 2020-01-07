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
        //callbacks.customizeUiComponent(main);
    }

    @Override
    public String getTabCaption() {
        return "SVODetect Results";
    }

    @Override
    public Component getUiComponent() {

        return main;
    }

    public UIMain getMain() {
        return main;
    }
}
