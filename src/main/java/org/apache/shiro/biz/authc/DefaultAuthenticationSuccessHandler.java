package org.apache.shiro.biz.authc;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.biz.ShiroBizMessageSource;
import org.apache.shiro.biz.authc.token.DefaultAuthenticationToken;
import org.apache.shiro.biz.utils.SubjectUtils;
import org.apache.shiro.biz.utils.WebUtils;
import org.apache.shiro.subject.Subject;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;

/**
 * 认证请求失败后的处理实现
 */
public class DefaultAuthenticationSuccessHandler  implements AuthenticationSuccessHandler {

	protected MessageSourceAccessor messages = ShiroBizMessageSource.getAccessor();
	 
	@Override
	public boolean supports(AuthenticationToken token) {
		return SubjectUtils.supports(token.getClass(), UsernamePasswordToken.class,
				DefaultAuthenticationToken.class);
	}

	@Override
	public void onAuthenticationSuccess(ServletRequest request, ServletResponse response,
			Subject subject) throws IOException, ServletException {
 
		HttpServletRequest httpRequest = WebUtils.toHttp(request);
		HttpServletResponse httpResponse = WebUtils.toHttp(response);
		
		httpResponse.setStatus(HttpStatus.UNAUTHORIZED.value());
		httpResponse.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
		 
		
	}

}
