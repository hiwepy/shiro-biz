package org.apache.shiro.biz.web.servlet.listener;

import org.apache.shiro.biz.utils.WebThreadContext;

import javax.servlet.ServletRequestEvent;
import javax.servlet.ServletRequestListener;
import javax.servlet.http.HttpServletRequest;

public class HttpServletRequestListener implements ServletRequestListener {

	@Override
	public void requestDestroyed(ServletRequestEvent requestEvent) {
		
	}

	@Override
	public void requestInitialized(ServletRequestEvent requestEvent) {
		if (!(requestEvent.getServletRequest() instanceof HttpServletRequest)) {
			throw new IllegalArgumentException( "Request is not an HttpServletRequest: " + requestEvent.getServletRequest());
		}
		HttpServletRequest request = (HttpServletRequest) requestEvent.getServletRequest();
		
		WebThreadContext.bindRequest(request);
		WebThreadContext.bindServletContext(request.getServletContext());
		
	}

}
