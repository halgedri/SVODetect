package gui;

import burp.IBurpExtenderCallbacks;

import javax.swing.*;

public class UIMain extends JTabbedPane {
    private IBurpExtenderCallbacks callbacks;

    private UIHowTo howTo;
    private UIAbout about;


    public UIMain(IBurpExtenderCallbacks callbacks) {

        this.callbacks = callbacks;
        initComponents();
    }

    public UIHowTo getHowTo() {

        return howTo;
    }


    public UIAbout getAbout() {
        return about;
    }


    private void initComponents() {

        howTo = new UIHowTo(callbacks);


        about = new UIAbout();

        this.addTab("How To", howTo);

        this.addTab("About", about);

        callbacks.customizeUiComponent(this);

    }
}
