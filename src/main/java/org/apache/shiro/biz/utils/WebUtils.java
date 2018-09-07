/*
 * Copyright (c) 2018, vindell (https://github.com/vindell).
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.apache.shiro.biz.utils;


import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.shiro.web.util.RequestPairSource;

import com.alibaba.fastjson.JSONObject;

public class WebUtils extends org.apache.shiro.web.util.WebUtils {

	private static String[] headers = new String[]{"Cdn-Src-Ip", "X-Real-IP", "X-Forwarded-For", "Proxy-Client-IP", "WL-Proxy-Client-IP", "HTTP_CLIENT_IP", "HTTP_X_FORWARDED_FOR"};
	private static String localIP = "127.0.0.1";
	private static String UNKNOWN = "unknown";    
	private static String LOCALHOST = "localhost";
	
	private static final String XML_HTTP_REQUEST = "XMLHttpRequest";
    private static final String X_REQUESTED_WITH = "X-Requested-With";

    private static final String CONTENT_TYPE = "Content-type";
    private static final String CONTENT_TYPE_JSON = "application/json; charset=utf-8";

    public static boolean isAjaxRequest(ServletRequest request) {
        return XML_HTTP_REQUEST.equals(toHttp(request).getHeader(X_REQUESTED_WITH));
    }

    public static boolean isContentTypeJson(ServletRequest request) {
        return toHttp(request).getHeader(CONTENT_TYPE).contains(CONTENT_TYPE_JSON);
    }
    
    public static boolean isWebRequest(RequestPairSource source) {
        ServletRequest request = source.getServletRequest();
        ServletResponse response = source.getServletResponse();
        return request != null && response != null;
    }

    public static boolean isHttpRequest(RequestPairSource source) {
        ServletRequest request = source.getServletRequest();
        ServletResponse response = source.getServletResponse();
        return request instanceof HttpServletRequest && response instanceof HttpServletResponse;
    }
    
    
    /**
	 * 获取请求客户端IP地址，支持代理服务器
	 * http://blog.csdn.net/caoshuming_500/article/details/20952329
	 * @param request {@link ServletRequest} 对象
	 * @return
	 */
	public static String getRemoteAddr(ServletRequest request) {
		
		// 1、获取客户端IP地址，支持代理服务器
		String remoteAddr = null;
		for (String header : headers) {
			remoteAddr = toHttp(request).getHeader(header);
			if(StringUtils.hasText(remoteAddr) && !UNKNOWN.equalsIgnoreCase(remoteAddr)){
				break;
			}
		}
		// 2、没有取得特定标记的值
		if(StringUtils.isEmpty(remoteAddr) ){
			remoteAddr = request.getRemoteAddr();
		}
		// 3、判断是否localhost访问
		if(LOCALHOST.equalsIgnoreCase(remoteAddr)){
			remoteAddr = localIP;
		}
		 
		return remoteAddr;
	}
	
	public static void writeJSONString(ServletResponse response, Map<String, Object> data)  {
    	
    	try {
			response.setCharacterEncoding("UTF-8");
			response.setContentType(CONTENT_TYPE_JSON);
			PrintWriter out = response.getWriter();
			out.write(JSONObject.toJSONString(data));
			out.flush();
		} catch (Exception e) {
		}
	}
	
    public static void writeJSONString(ServletResponse response, int status, String message)  {
    	
    	try {
			Map<String, Object> data = new HashMap<String, Object>();
			data.put("status", status);
			data.put("message", message);
			response.setCharacterEncoding("UTF-8");
			response.setContentType(CONTENT_TYPE_JSON);
			PrintWriter out = response.getWriter();
			out.write(JSONObject.toJSONString(data));
			out.flush();
		} catch (Exception e) {
		}
	}
    
}

