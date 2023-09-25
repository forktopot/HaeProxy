package org.example;

/**
 * Hello world!
 *
 */
import burp.*;
import javax.swing.*;
import java.awt.*;
import java.io.OutputStream;
import java.net.Socket;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

//public class BurpPlugin implements IBurpExtender, IHttpListener {
//    private IBurpExtenderCallbacks callbacks;
//    private IExtensionHelpers helpers;
////    private Gson gson;
//
//    @Override
//    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
//        this.callbacks = callbacks;
//        this.helpers = callbacks.getHelpers();
////        this.gson = new Gson();
//
//        callbacks.setExtensionName("Burp Plugin");
//
//        callbacks.registerHttpListener(this);
//    }
//
//    @Override
//    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
////            IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);
////            String url = requestInfo.getUrl().toString();
//            byte[] response = messageInfo.getResponse();
//            byte[] request = messageInfo.getRequest();
//            sendToServer(URLEncoder.encode(new String(request)), URLEncoder.encode(new String(response)));
//    }
//
//    private void sendToServer(String request, String response) {
//        try {
//            Socket socket = new Socket("127.0.0.1", 18989);
//            OutputStream out = socket.getOutputStream();
//
//            Map<String, String> map = new HashMap<>();
////            map.put("url", url);
//            map.put("request", request);
//            map.put("response", response);
//            String json = mapToJson(map);
//
//            out.write(json.getBytes(StandardCharsets.UTF_8));
//            out.flush();
//            out.close();
//            socket.close();
//        } catch (Exception e) {
//            callbacks.printError(e.getMessage());
//        }
//    }
//
//    private String mapToJson(Map<String, String> map) {
//        StringBuilder sb = new StringBuilder();
//        sb.append("{");
//        for (Map.Entry<String, String> entry : map.entrySet()) {
//            sb.append("\"").append(entry.getKey()).append("\":\"").append(entry.getValue()).append("\",");
//        }
//        sb.deleteCharAt(sb.length() - 1);
//        sb.append("}");
//        return sb.toString();
//    }
//}


public class BurpPlugin implements IBurpExtender, IHttpListener {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private JPanel panel;
    private JCheckBox checkBox;
    private JTextField addressField;
    private JTextField portField;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();

        callbacks.setExtensionName("HaeProxy v1.0");

        // Create a new panel for the Tab
        panel = new JPanel();
        panel.setLayout(new GridLayout(3, 2));

        // Create a new checkbox for the switch
        checkBox = new JCheckBox("Enable Listener");
        panel.add(checkBox);

        // Create a new text field for the address
        panel.add(new JLabel("Address:"));
        addressField = new JTextField("127.0.0.1");
        panel.add(addressField);

        // Create a new text field for the port
        panel.add(new JLabel("Port:"));
        portField = new JTextField("18989");
        panel.add(portField);

        // Add the panel to the Burp Tab
        callbacks.customizeUiComponent(panel);

        callbacks.addSuiteTab(new ITab() {
            @Override
            public String getTabCaption() {
                return "HaeProxy";
            }

            @Override
            public Component getUiComponent() {
                return panel;
            }
        });

        callbacks.registerHttpListener(this);
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (!checkBox.isSelected()) {
            return;
        }

        byte[] response = messageInfo.getResponse();
        byte[] request = messageInfo.getRequest();
        sendToServer(URLEncoder.encode(new String(request)), URLEncoder.encode(new String(response)));
    }

    private void sendToServer(String request, String response) {
        try {
            String address = addressField.getText();
            int port = Integer.parseInt(portField.getText());
            Socket socket = new Socket(address, port);
            OutputStream out = socket.getOutputStream();

            Map<String, String> map = new HashMap<>();
            map.put("request", request);
            map.put("response", response);
            String json = mapToJson(map);

            out.write(json.getBytes(StandardCharsets.UTF_8));
            out.flush();
            out.close();
            socket.close();
        } catch (Exception e) {
            callbacks.printError(e.getMessage());
        }
    }

    private String mapToJson(Map<String, String> map) {
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        for (Map.Entry<String, String> entry : map.entrySet()) {
            sb.append("\"").append(entry.getKey()).append("\":\"").append(entry.getValue()).append("\",");
        }
        sb.deleteCharAt(sb.length() - 1);
        sb.append("}");
        return sb.toString();
    }
}