package top.oxff.control;

import burp.BurpExtender;
import burp.IExtensionHelpers;
import burp.IHttpListener;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IResponseInfo;
import top.oxff.model.HeaderItem;
import top.oxff.service.ResponseHeaderHandler;
import top.oxff.service.ResponseHeaderService;
import top.oxff.util.BytesTools;

import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

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
        if (messageIsRequest) {
            if (!TOOL_FLAGS.contains(toolFlag) || null == httpRequestResponse || tableModel.isEmpty()) {
                return;
            }
            processRequest(toolFlag, httpRequestResponse);
        } else {
            if (null == httpRequestResponse || !ResponseHeaderService.isActive(toolFlag)) {
                return;
            }
            processResponse(httpRequestResponse);
        }
    }

    /**
     * 处理请求头替换
     *
     * @param toolFlag            Burp工具标志
     * @param httpRequestResponse 请求响应对象
     */
    private void processRequest(int toolFlag, IHttpRequestResponse httpRequestResponse) {
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

    /**
     * 处理响应头改写
     * 由注册在 {@link ResponseHeaderService} 中的处理器决定具体改写逻辑，
     * 没有任何头发生变化时不重建响应报文
     *
     * @param httpRequestResponse 请求响应对象
     */
    private void processResponse(IHttpRequestResponse httpRequestResponse) {
        try {
            byte[] data = httpRequestResponse.getResponse();
            if (null == data || 0 == data.length) {
                return;
            }

            IResponseInfo responseInfo = extensionHelpers.analyzeResponse(data);
            if (null == responseInfo) {
                return;
            }

            List<String> headers = responseInfo.getHeaders();
            if (null == headers || headers.isEmpty()) {
                return;
            }

            List<ResponseHeaderHandler> handlers = ResponseHeaderService.getHandlers();
            List<String> tmpHeaders = new ArrayList<>(headers);
            Set<String> hitHeaderNames = new HashSet<>();
            boolean changed = false;

            for (int i = 1; i < tmpHeaders.size(); i++) {
                String header = tmpHeaders.get(i);
                if (null == header || !header.contains(":")) {
                    continue;
                }

                String[] headerArr = header.split(":", 2);
                if (2 != headerArr.length) {
                    continue;
                }

                String name = headerArr[0].trim();
                for (ResponseHeaderHandler handler : handlers) {
                    if (!handler.isEnabled() || !name.equalsIgnoreCase(handler.getHeaderName())) {
                        continue;
                    }

                    hitHeaderNames.add(handler.getHeaderName().toLowerCase());
                    String newValue = handler.transform(headerArr[1].trim());
                    if (null == newValue || newValue.equals(headerArr[1].trim())) {
                        break;
                    }

                    tmpHeaders.set(i, String.format("%s: %s", name, newValue));
                    changed = true;
                    break;
                }
            }

            for (ResponseHeaderHandler handler : handlers) {
                if (!handler.isEnabled() || !handler.isAddIfMissing()
                        || hitHeaderNames.contains(handler.getHeaderName().toLowerCase())) {
                    continue;
                }

                String newValue = handler.transform(null);
                if (null == newValue) {
                    continue;
                }

                tmpHeaders.add(String.format("%s: %s", handler.getHeaderName(), newValue));
                changed = true;
            }

            if (!changed) {
                return;
            }

            int offSet = responseInfo.getBodyOffset();
            byte[] body = BytesTools.subByteArray(data, offSet, data.length - offSet);

            httpRequestResponse.setResponse(extensionHelpers.buildHttpMessage(tmpHeaders, body));
        } catch (Exception e) {
            // 改写失败时保留原始响应，避免破坏正常流量
            BurpExtender.logError("process response headers error: " + e.getMessage());
        }
    }
}
