package top.oxff.control;

import burp.IExtensionHelpers;
import burp.IHttpListener;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import top.oxff.model.HeaderItem;
import top.oxff.util.BytesTools;

import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static burp.BurpExtender.TOOL_FLAGS;
import static burp.BurpExtender.tableModel;

public class HttpProcess implements IHttpListener {
    IExtensionHelpers extensionHelpers;
    PrintWriter stdout;
    PrintWriter stderr;


    public HttpProcess(IExtensionHelpers extensionHelpers, PrintWriter stdout, PrintWriter stderr) {
        this.extensionHelpers = extensionHelpers;
        this.stdout = stdout;
        this.stderr = stderr;
    }
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse httpRequestResponse) {
        if (!TOOL_FLAGS.contains(toolFlag) || (!messageIsRequest || null == httpRequestResponse || tableModel.isEmpty())) {
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
        if (headers.isEmpty()) {
            return;
        }

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
            if (2 != header_arr.length) {
                continue;
            }

            String key = header_arr[0].trim();

            if (tableModel.isExist(key) && tableModel.isEnableTool(toolFlag, key)) {
                kvsCntMap.put(header_arr[0].trim(), kvsCntMap.getOrDefault(key, 0) + 1);
                tmpHeaders.remove(header);
                tmpHeaders.add(String.format("%s: %s", header_arr[0].trim(), tableModel.getValueByKey(key)));
            }
        }

        for (HeaderItem headerItem : tableModel.getHeaderItemList()) {
            String key = headerItem.getKey();
            if (0 == kvsCntMap.getOrDefault(key, 0) && tableModel.isEnableTool(toolFlag, key)) {
                tmpHeaders.add(String.format("%s: %s", headerItem.getKey(), headerItem.getValue()));
            }
        }

        int offSet = requestInfo.getBodyOffset();
        byte[] body = BytesTools.subByteArray(data, offSet, data.length - offSet);

        byte[] finalData = extensionHelpers.buildHttpMessage(tmpHeaders, body);

        httpRequestResponse.setRequest(finalData);
    }
}
