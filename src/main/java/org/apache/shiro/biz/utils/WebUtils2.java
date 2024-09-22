/*
 * Copyright (c) 2018, hiwepy (https://github.com/hiwepy).
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

import com.google.common.net.HttpHeaders;
import org.apache.shiro.lang.ShiroException;
import org.apache.shiro.web.util.RequestPairSource;
import org.springframework.http.HttpMethod;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

public class WebUtils2 {

	private static String[] headers = new String[]{"Cdn-Src-Ip", "X-Real-IP", "X-Forwarded-For", "Proxy-Client-IP", "WL-Proxy-Client-IP", "HTTP_CLIENT_IP", "HTTP_X_FORWARDED_FOR"};
	private static String localIP = "127.0.0.1";
	private static String UNKNOWN = "unknown";    
	private static String LOCALHOST = "localhost";
	
	private static final String XML_HTTP_REQUEST = "XMLHttpRequest";
    private static final String CONTENT_TYPE_JSON = "application/json";

	public static boolean isAjaxResponse(HttpServletRequest request) {
		return isAjaxRequest(request) || isContentTypeJson(request) || isPostRequest(request);
	}

    public static boolean isObjectRequest(ServletRequest request) {
        return isPostRequest(request) && isContentTypeJson(request);
    }
    
    public static boolean isAjaxRequest(HttpServletRequest request) {
        return XML_HTTP_REQUEST.equals(request.getHeader(HttpHeaders.X_REQUESTED_WITH));
    }
    
    public static boolean isAjaxRequest(ServletRequest request) {
        try {
			return XML_HTTP_REQUEST.equals(org.apache.shiro.web.util.WebUtils.toHttp(request).getHeader(HttpHeaders.X_REQUESTED_WITH));
		} catch (Exception e) {
			return false;
		}
    }

    public static boolean isContentTypeJson(HttpServletRequest request) {
        return request.getHeader(HttpHeaders.CONTENT_TYPE).contains(CONTENT_TYPE_JSON);
    }
    
    public static boolean isContentTypeJson(ServletRequest request) {
        try {
			return org.apache.shiro.web.util.WebUtils.toHttp(request).getHeader(HttpHeaders.CONTENT_TYPE).contains(CONTENT_TYPE_JSON);
		} catch (Exception e) {
			return false;
		}
    }
    
    
    public static boolean isPostRequest(HttpServletRequest request) {
        return HttpMethod.POST.name().equals(request.getMethod());
    }
    
    public static boolean isPostRequest(ServletRequest request) {
        return HttpMethod.POST.name().equals(org.apache.shiro.web.util.WebUtils.toHttp(request).getMethod());
    }
     
	public static boolean isAjaxResponse(ServletRequest request) {
		return isAjaxRequest(request) || isContentTypeJson(request) || isPostRequest(request);
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
	 * @return ip
	 */
	public static String getRemoteAddr(ServletRequest request) {
		
		// 1、获取客户端IP地址，支持代理服务器
		String remoteAddr = null;
		for (String header : headers) {
			remoteAddr = org.apache.shiro.web.util.WebUtils.toHttp(request).getHeader(header);
			if(org.apache.shiro.lang.util.StringUtils.hasText(remoteAddr) && !UNKNOWN.equalsIgnoreCase(remoteAddr)){
				break;
			}
		}
		// 2、没有取得特定标记的值
		if(StringUtils2.isEmpty(remoteAddr) ){
			remoteAddr = request.getRemoteAddr();
		}
		// 3、判断是否localhost访问
		if(LOCALHOST.equalsIgnoreCase(remoteAddr)){
			remoteAddr = localIP;
		}
		 
		return remoteAddr;
	}
    
	

    /**
     * Add a new parameter to an url.
     *
     * @param url   url
     * @param name  name of the parameter
     * @param value value of the parameter
     * @return the new url with the parameter appended
     */
    public static String addParameter(final String url, final String name, final String value) {
        if (url != null) {
            final StringBuilder sb = new StringBuilder();
            sb.append(url);
            if (name != null) {
                if (url.indexOf("?") >= 0) {
                    sb.append("&");
                } else {
                    sb.append("?");
                }
                sb.append(name);
                sb.append("=");
                if (value != null) {
                    sb.append(urlEncode(value));
                }
            }
            return sb.toString();
        }
        return null;
    }

    /**
     * URL encode a text using UTF-8.
     *
     * @param text text to encode
     * @return the encoded text
     */
    public static String urlEncode(final String text) {
        try {
            return URLEncoder.encode(text, StandardCharsets.UTF_8.name());
        } catch (final UnsupportedEncodingException e) {
            final String message = "Unable to encode text : " + text;
            throw new ShiroException(message, e);
        }
    }
    
}

