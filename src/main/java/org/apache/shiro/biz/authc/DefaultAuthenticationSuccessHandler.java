package org.apache.shiro.biz.authc;

import java.io.IOException;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.biz.ShiroBizMessageSource;
import org.apache.shiro.biz.authc.token.DefaultAuthenticationToken;
import org.apache.shiro.biz.utils.SubjectUtils;
import org.apache.shiro.biz.utils.WebUtils;
import org.apache.shiro.biz.web.servlet.http.HttpStatus;
import org.apache.shiro.subject.Subject;
import org.springframework.context.NoSuchMessageException;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.core.Ordered;
import org.springframework.http.MediaType;

import com.alibaba.fastjson.JSONObject;

/**
 * 认证请求成功后的处理实现
 */
public class DefaultAuthenticationSuccessHandler  implements AuthenticationSuccessHandler {

	protected MessageSourceAccessor messages = ShiroBizMessageSource.getAccessor();
	 
	@Override
	public boolean supports(AuthenticationToken token) {
		return SubjectUtils.isAssignableFrom(token.getClass(), UsernamePasswordToken.class,
				DefaultAuthenticationToken.class);
	}

	@Override
	public void onAuthenticationSuccess(AuthenticationToken token, ServletRequest request, ServletResponse response,
			Subject subject) {
 
		try {
			//HttpServletRequest httpRequest = WebUtils.toHttp(request);
			HttpServletResponse httpResponse = WebUtils.toHttp(response);
			
			httpResponse.setStatus(HttpStatus.SC_OK);
			httpResponse.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
			
			// Response Authentication status information
			JSONObject.writeJSONString(response.getWriter(), AuthcResponse.success(messages.getMessage(AuthcResponseCode.SC_AUTHC_SUCCESS.getMsgKey())));
			
		} catch (NoSuchMessageException e) {
			throw new AuthenticationException(e);
		} catch (IOException e) {
			throw new AuthenticationException(e);
		}
		
	}

	@Override
	public int getOrder() {
		return Integer.MIN_VALUE;
	}
	
}
