package burp;

import top.oxff.control.ContextMenuFactoryIml;
import top.oxff.ui.TabUI;
import top.oxff.util.RowItem;

import java.awt.*;
import java.io.PrintWriter;
import java.util.*;
import java.util.List;

public class BurpExtender implements IBurpExtender, ITab, IHttpListener, IExtensionStateListener {
    final static String NAME = "changeHeaders";

    public static IBurpExtenderCallbacks burpExtenderCallbacks;

    IExtensionHelpers extensionHelpers;

    public static PrintWriter stdout;
    public static PrintWriter stderr;

    public static Map<String, String> KVS = new HashMap<>();

    public final static Set<Integer> Tool_flags = new HashSet<>();

    public final static String KVS_SEP = "//__//";
    public final static String SEP = "//_//";

    private final static String KVS_EX_NAME = "KVS";
    private final static String Tool_FLag_EX_NAME = "TOOL_FLAG";

    static TabUI tabUI;

    public static void addKVITem(String k, String v, String ev) {
        boolean flag = false;
        if (KVS.containsKey(k)) {
            flag = true;
            KVS.remove(k, v);
        }
        KVS.put(k, v);

        if (flag) {
            String desc = tabUI.getRowItemByKey(k).getDesc();
            tabUI.updateRowByKey(new RowItem(k, v, ev, desc));
        } else {
            tabUI.addRow(new RowItem(k, v, ev, ""));
        }

    }


    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks burpExtenderCallbacks) {
        BurpExtender.burpExtenderCallbacks = burpExtenderCallbacks;

        burpExtenderCallbacks.setExtensionName(NAME);

        extensionHelpers = burpExtenderCallbacks.getHelpers();

        stdout = new PrintWriter(BurpExtender.burpExtenderCallbacks.getStdout(), true);
        stderr = new PrintWriter(BurpExtender.burpExtenderCallbacks.getStderr(), true);

        tabUI = new TabUI();

        ContextMenuFactoryIml contextMenuFactoryIml = new ContextMenuFactoryIml();

        BurpExtender.burpExtenderCallbacks.addSuiteTab(this);
        BurpExtender.burpExtenderCallbacks.registerHttpListener(this);
        BurpExtender.burpExtenderCallbacks.registerContextMenuFactory(contextMenuFactoryIml);
        BurpExtender.burpExtenderCallbacks.registerExtensionStateListener(this);

        loadExConfig();


    }


    private void saveExConfig() {
        List<String> KVS_StringList = new ArrayList<>();
        List<RowItem> rowItems = tabUI.getRowItems();
        for (RowItem rowItem : rowItems) {
            if (null == rowItem){
                continue;
            }
            String item = rowItem.getHeaderKey() + KVS_SEP + rowItem.getHeaderValue() + KVS_SEP + rowItem.getEnable() + KVS_SEP+rowItem.getDesc();
            KVS_StringList.add(item);
        }

        String KVS_Settings_str = String.join(SEP, KVS_StringList);
//        stdout.println(String.format("KVS_Settings_str -->%s", KVS_Settings_str));
        // base64 encode and then save
//        KVS_Settings_str = Base64.getEncoder().encodeToString(KVS_Settings_str.getBytes());
        burpExtenderCallbacks.saveExtensionSetting(KVS_EX_NAME, KVS_Settings_str);

        List<String> tool_flags_strList = new ArrayList<>();

        for (Integer tool_flag : Tool_flags) {
            tool_flags_strList.add(Integer.toString(tool_flag));
        }

        String Tool_flags_str = String.join(SEP, tool_flags_strList);
        burpExtenderCallbacks.saveExtensionSetting(Tool_FLag_EX_NAME, Tool_flags_str);
    }


    private void loadExConfig() {
        String KVS_EX_Setting_str = burpExtenderCallbacks.loadExtensionSetting(KVS_EX_NAME);
        // base64 decode and then load
//        KVS_EX_Setting_str = new String(Base64.getDecoder().decode(KVS_EX_Setting_str));
//        stdout.println(String.format("KVS_EX_Setting_str --> %s", KVS_EX_Setting_str));
        if (null != KVS_EX_Setting_str && !KVS_EX_Setting_str.trim().isEmpty() && KVS_EX_Setting_str.contains(KVS_SEP)) {
            String[] KVS_EX_Setting_items;
            if (KVS_EX_Setting_str.contains(SEP)) {
                KVS_EX_Setting_items = KVS_EX_Setting_str.split(SEP);
            } else {
                KVS_EX_Setting_items = new String[]{KVS_EX_Setting_str};
            }

            for (String itemStr : KVS_EX_Setting_items) {
//                stdout.println(String.format("itemStr --> %s", itemStr));
                if (null == itemStr || !itemStr.contains(KVS_SEP)) {
                    continue;
                }

                String[] KVS_EX_Setting_Item_values = itemStr.split(KVS_SEP);
                if (null == KVS_EX_Setting_Item_values || KVS_EX_Setting_Item_values.length == 0){
                    continue;
                }
                tabUI.addRow(new RowItem(KVS_EX_Setting_Item_values[0], KVS_EX_Setting_Item_values[1], KVS_EX_Setting_Item_values[2], KVS_EX_Setting_Item_values.length != 4 ? "" : KVS_EX_Setting_Item_values[3]));
                if (KVS_EX_Setting_Item_values[2].equals("是")) {
                    KVS.put(KVS_EX_Setting_Item_values[0], KVS_EX_Setting_Item_values[1]);
                }
            }
        }

        String tool_flag_str = burpExtenderCallbacks.loadExtensionSetting(Tool_FLag_EX_NAME);
        if (null != tool_flag_str && !tool_flag_str.trim().isEmpty()) {
            String[] tools_arr;
            if (tool_flag_str.contains(SEP)) {
                tools_arr = tool_flag_str.split(SEP);
            } else {
                tools_arr = new String[]{tool_flag_str};
            }

            for (String s : tools_arr) {
                tabUI.setCheckBoxStatus(Integer.parseInt(s), true);
                Tool_flags.add(Integer.parseInt(s));
            }
        }
    }


    @Override
    public void extensionUnloaded() {
        saveExConfig();
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse httpRequestResponse) {
        if (!Tool_flags.contains(toolFlag)) {
//            stdout.println("BurpExtender  -->154");
            return;
        } else if (!messageIsRequest || null == httpRequestResponse || 0 == KVS.size()) {
//            stdout.println("BurpExtender  -->154");
            return;
        }

        byte[] data = httpRequestResponse.getRequest();
        if (0 == data.length) {
            return;
        }

        IRequestInfo requestInfo = extensionHelpers.analyzeRequest(httpRequestResponse);
        if (null == requestInfo) {
            return;
        }

        List<String> headers = requestInfo.getHeaders();

        if (0 == headers.size()) {
            return;
        }

//        for (String k : KVS.keySet()) {
//
//            for (String header : headers) {
//                if (header.contains(k)) {
//                    headers.remove(header);
//                    break;
//                }
//            }
//            headers.add(String.format("%s: %s", k, KVS.get(k)));
//
//        }

        List<String> tmpHeaders = new ArrayList<>(headers);
        Map<String, Integer> kvsCntMap = new HashMap<>();
        for (int i = 0; i < headers.size(); i++) {
            if (0 == i){
                continue;
            }

            String header = headers.get(i);
            if (!header.contains(":")) {
                continue;
            }

            String[] header_arr = header.split(":", 2);
            if (null == header_arr || 2 != header_arr.length) {
                continue;
            }

            if (KVS.containsKey(header_arr[0].trim())) {

                kvsCntMap.put(header_arr[0].trim(), kvsCntMap.getOrDefault(header_arr[0].trim(), 0) + 1);
                tmpHeaders.remove(header);
                tmpHeaders.add(String.format("%s: %s", header_arr[0].trim(), KVS.get(header_arr[0].trim())));
            }
        }

        KVS.forEach((k, v) -> {
            if (0 == kvsCntMap.getOrDefault(k, 0)) {
                tmpHeaders.add(String.format("%s: %s", k, v));
            }
        });

        headers = tmpHeaders;


//        stdout.println("BurpExtender  -->186");

        int offSet = requestInfo.getBodyOffset();
        byte[] body = subByteArray(data, offSet, data.length - offSet);

        byte[] finalData = extensionHelpers.buildHttpMessage(headers, body);

        httpRequestResponse.setRequest(finalData);
    }

    public byte[] subByteArray(byte[] src, int off, int length) {
        byte[] ret = new byte[length];
        System.arraycopy(src, off, ret, 0, length);

        return ret;
    }

    @Override
    public String getTabCaption() {
        return NAME;
    }

    @Override
    public Component getUiComponent() {
        return tabUI;
    }
}
