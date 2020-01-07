package gui;

import com.intellij.uiDesigner.core.GridConstraints;
import com.intellij.uiDesigner.core.GridLayoutManager;
import com.intellij.uiDesigner.core.Spacer;

import javax.swing.*;
import java.awt.*;

public class UIAbout extends javax.swing.JPanel{

    public UIAbout(){
        initComponents();

    }

    private void initComponents() {

        helpPanel = new JPanel();
        textLabel = new JLabel();
        setEnabled(false);

        textLabel.setText("SVO Detect, 2020");



    }

    private JPanel helpPanel;
    private JLabel textLabel;



}
