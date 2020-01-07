package gui;

import burp.IBurpExtenderCallbacks;

import javax.swing.*;

public class UIMain extends JTabbedPane {

    private IBurpExtenderCallbacks callbacks;

    private UIHowTo howTo;
    private UIResultGraph resultGraph;
    private UIAbout about;


    public UIMain(IBurpExtenderCallbacks callbacks) {

        this.callbacks = callbacks;
        initComponents();
    }

    public UIHowTo getHowTo(){

        return howTo;
    }

    public UIResultGraph getResultGraph(){
        return resultGraph;
    }

    public UIAbout getAbout(){
        return about;
    }

    private void initComponents() {

        howTo = new UIHowTo(callbacks);

        resultGraph = new UIResultGraph(callbacks);

        about = new UIAbout();

        this.addTab("How To", howTo);

        this.addTab("Results", resultGraph);

         this.addTab("About", about);
    }
}
