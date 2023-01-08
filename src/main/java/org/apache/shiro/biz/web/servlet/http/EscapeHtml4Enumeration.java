package org.apache.shiro.biz.web.servlet.http;

import org.apache.commons.text.StringEscapeUtils;

import java.util.Enumeration;

public class EscapeHtml4Enumeration implements Enumeration<String> {

	private Enumeration<String> headers;
	
	public EscapeHtml4Enumeration(Enumeration<String> headers){
		this.headers = headers;
	}
	
	@Override
	public boolean hasMoreElements() {
		return headers.hasMoreElements();
	}

	@Override
	public String nextElement() {
		return StringEscapeUtils.escapeHtml4(headers.nextElement());
	}

}
