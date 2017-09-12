package org.apache.shiro.biz.web.servlet.filter;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.apache.shiro.biz.utils.WebThreadContext;
import org.apache.shiro.web.servlet.OncePerRequestFilter;

/**
 * 
 * @className	： HttpServletRequestBindFilter
 * @description	： WebThreadContext对象绑定过滤器
 * @author 		： <a href="https://github.com/vindell">vindell</a>
 * @date		： 2017年8月26日 下午6:13:49
 * @version 	V1.0
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
