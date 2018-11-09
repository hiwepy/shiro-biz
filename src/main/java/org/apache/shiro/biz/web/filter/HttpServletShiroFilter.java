package org.apache.shiro.biz.web.filter;

import org.apache.shiro.web.servlet.AbstractShiroFilter;

public class HttpServletShiroFilter extends AbstractShiroFilter {
	
	/*@Override
	protected WebSubject createSubject(ServletRequest request, ServletResponse response) {
		Subject subject = super.createSubject(request, response);
        if (subject == null) {
            ThreadContext.bind(subject);
        }
        return (WebSubject) subject;
	}*/
	
}
