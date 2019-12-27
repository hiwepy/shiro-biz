package org.apache.shiro.biz.web.servlet.filter;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.apache.shiro.biz.utils.WebThreadContext;
import org.apache.shiro.web.servlet.OncePerRequestFilter;

/**
 * WebThreadContext对象绑定过滤器
 * @author <a href="https://github.com/hiwepy">hiwepy</a>
 */
public class HttpServletRequestBindFilter extends OncePerRequestFilter {
	
	@Override
	public void doFilterInternal(ServletRequest request, ServletResponse response, FilterChain chain)
			throws ServletException, IOException {
		WebThreadContext.bindRequest(request);
		WebThreadContext.bindResponse(response);
		chain.doFilter(request, response);
	}
	
}
