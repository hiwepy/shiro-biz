package org.apache.shiro.biz.web.filter;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.ThreadContext;
import org.apache.shiro.web.servlet.AbstractShiroFilter;
import org.apache.shiro.web.subject.WebSubject;

public class HttpServletShiroFilter extends AbstractShiroFilter {
	
	@Override
	protected WebSubject createSubject(ServletRequest request, ServletResponse response) {
		Subject subject = super.createSubject(request, response);
        if (subject == null) {
            ThreadContext.bind(subject);
        }
        return (WebSubject) subject;
	}
	
}
