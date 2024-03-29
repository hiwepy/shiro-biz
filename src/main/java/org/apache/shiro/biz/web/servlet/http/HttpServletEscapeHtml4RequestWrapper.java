package org.apache.shiro.biz.web.servlet.http;

import org.apache.commons.text.StringEscapeUtils;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;


/**
 * 使用 StringEscapeUtils.escapeHtml4()对Http请求中的  Parameter，Header 进行统一的转码处理
 * @author 		： <a href="https://github.com/hiwepy">hiwepy</a>
 */
public class HttpServletEscapeHtml4RequestWrapper extends HttpServletRequestWrapper {
	
	public HttpServletEscapeHtml4RequestWrapper(HttpServletRequest request) {
		super(request);
	}
	
	@Override
	public Map<String, String[]> getParameterMap() {
		Map<String, String[]> request_map = super.getParameterMap();
		Iterator<Entry<String, String[]>> iterator = request_map.entrySet().iterator();
		while (iterator.hasNext()) {
			Entry<String, String[]> me = iterator.next();
			String[] values = (String[]) me.getValue();
			for (int i = 0; i < values.length; i++) {
				// /System.out.println(values[i]);
				values[i] = xssClean(values[i]);
			}
		}
		return request_map;
	}

	@Override
	public String[] getParameterValues(String name) {
		String[] rawValues = super.getParameterValues(name);
		if (rawValues == null){
			return null;
		}
		String[] cleanedValues = new String[rawValues.length];
		for (int i = 0; i < rawValues.length; i++) {
			cleanedValues[i] = xssClean(rawValues[i]);
		}
		return cleanedValues;
	}

	@Override
	public String getParameter(String name) {
		String str = super.getParameter(name);
		if (str == null){
			return null;
		}
		return xssClean(str);
	}

	@Override
	public Enumeration<String> getHeaders(String name) {
        return new EscapeHtml4Enumeration(super.getHeaders(name));
    }
	
	@Override
	public String getHeader(String name) {
		String str = super.getHeader(name);
		if (str == null){
			return null;
		}
		return xssClean(str);
	}
	
	@Override
	public Cookie[] getCookies() {
		Cookie[] existingCookies = super.getCookies();
		if (existingCookies != null) {
			for (int i = 0; i < existingCookies.length; ++i) {
				Cookie cookie = existingCookies[i];
				cookie.setValue(xssClean(cookie.getValue()));
			}
		}
		return existingCookies;
	}

	@Override
	public String getQueryString() {
		return xssClean(super.getQueryString());
	}

	public String xssClean(String taintedHTML) {
		return StringEscapeUtils.escapeHtml4(taintedHTML);
	}
	
	protected HttpServletRequest getHttpServletRequest() {
		 return (HttpServletRequest) super.getRequest();
    }

}
