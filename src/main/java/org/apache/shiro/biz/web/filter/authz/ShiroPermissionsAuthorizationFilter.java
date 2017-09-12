package org.apache.shiro.biz.web.filter.authz;

import java.io.IOException;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.apache.shiro.ShiroException;
import org.apache.shiro.web.filter.authz.PermissionsAuthorizationFilter;

public class ShiroPermissionsAuthorizationFilter extends PermissionsAuthorizationFilter {

	@Override
	protected void redirectToLogin(ServletRequest request, ServletResponse response) throws IOException {
		
		throw new ShiroException("身份异常，不进行转发到登录页面");
		
		/*
		 * 解决了页面没有刷新点击功能，但是后台的author已经被注销的情况下会去发送cas请求而产生的跨域问题
		 * 
		 * String loginUrl = getLoginUrl(); 
		 * WebUtils.issueRedirect(request, response, loginUrl);
		 * 
		 */
		
	}

}