package burp;

import com.alibaba.fastjson2.JSON;
import top.oxff.control.ContextMenuFactoryIml;
import top.oxff.control.HttpProcess;
import top.oxff.model.ExtenderConfig;
import top.oxff.model.HeaderItemTableModel;
import top.oxff.ui.TabUI;

import javax.swing.*;
import java.awt.*;
import java.io.PrintWriter;
import java.util.*;

public class BurpExtender implements IBurpExtender, ITab, IExtensionStateListener {
    final static String NAME = "changeHeaders_v1.9.0";

    public static IBurpExtenderCallbacks burpExtenderCallbacks;

    public static IExtensionHelpers extensionHelpers;

    public static PrintWriter stdout;
    public static PrintWriter stderr;

    public static final int TOOL_FLAG_POPUP_MENU = 666666;

    public final static Set<Integer> TOOL_FLAGS = new HashSet<>();

    private final static String ExtenderConfig_NAME = "changeHeadersExtenderConfig";

    static TabUI tabUI;
    public static HeaderItemTableModel tableModel;


    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks burpExtenderCallbacks) {
        BurpExtender.burpExtenderCallbacks = burpExtenderCallbacks;

        burpExtenderCallbacks.setExtensionName(NAME);

        extensionHelpers = burpExtenderCallbacks.getHelpers();

        stdout = new PrintWriter(BurpExtender.burpExtenderCallbacks.getStdout(), true);
        stderr = new PrintWriter(BurpExtender.burpExtenderCallbacks.getStderr(), true);

        tableModel = new HeaderItemTableModel();
        tabUI = new TabUI();

        ContextMenuFactoryIml contextMenuFactoryIml = new ContextMenuFactoryIml();

        BurpExtender.burpExtenderCallbacks.addSuiteTab(this);
        BurpExtender.burpExtenderCallbacks.registerHttpListener(new HttpProcess(extensionHelpers, stdout, stderr));
        BurpExtender.burpExtenderCallbacks.registerContextMenuFactory(contextMenuFactoryIml);
        BurpExtender.burpExtenderCallbacks.registerExtensionStateListener(this);

        SwingUtilities.invokeLater(this::loadExConfig);

        // 输出作者版本等信息
        logInfo("Author: " + "oxff01");
        logInfo("Version: " + "1.9.0");
        logInfo("Github: " + "https://github.com/oxff01/changeHeaders");
    }


    private void saveExConfig() {
        ExtenderConfig extenderConfig = tabUI.getExtenderConfig();
        String jsonString = JSON.toJSONString(extenderConfig);
        burpExtenderCallbacks.saveExtensionSetting(ExtenderConfig_NAME, jsonString);
    }


    private void loadExConfig() {
        String jsonString = burpExtenderCallbacks.loadExtensionSetting(ExtenderConfig_NAME);
        if (null == jsonString || jsonString.isEmpty() || jsonString.trim().isEmpty()){
            return;
        }
        try {
            ExtenderConfig config = JSON.parseObject(jsonString, ExtenderConfig.class);
            tabUI.setCheckBoxStatus(config);
            if (null != config.getKeyMap() && !config.getKeyMap().isEmpty()) {
                tableModel.setKeyMap(config.getKeyMap());
            }
            if (null != config.getHeaderItemList() && !config.getHeaderItemList().isEmpty()) {
                tableModel.setHeaderItemList(config.getHeaderItemList());
            }
            if(null != config.getToolFlags() && !config.getToolFlags().isEmpty()){
                TOOL_FLAGS.addAll(config.getToolFlags());
            }
        }catch (Exception e){
            stdout.println("parse json object error: " + e.getMessage());
        }
    }


    @Override
    public void extensionUnloaded() {
        saveExConfig();
    }

    @Override
    public String getTabCaption() {
        return NAME;
    }

    @Override
    public Component getUiComponent() {
        return tabUI;
    }

    public static void logInfo(String info) {
        stdout.println(info);
    }

    public static void logError(String error) {
        stderr.println(error);
    }

}
