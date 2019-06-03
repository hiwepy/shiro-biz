package org.apache.shiro.biz.authc;

import java.io.IOException;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.biz.ShiroBizMessageSource;
import org.apache.shiro.biz.authc.exception.CaptchaSendException;
import org.apache.shiro.biz.authc.exception.ExpiredCaptchaException;
import org.apache.shiro.biz.authc.exception.ExpiredTokenException;
import org.apache.shiro.biz.authc.exception.IncorrectCaptchaException;
import org.apache.shiro.biz.authc.exception.IncorrectTokenException;
import org.apache.shiro.biz.authc.exception.InvalidCaptchaException;
import org.apache.shiro.biz.authc.exception.InvalidTokenException;
import org.apache.shiro.biz.authc.exception.NoneCaptchaException;
import org.apache.shiro.biz.authc.exception.NoneTokenException;
import org.apache.shiro.biz.authc.exception.OverRetryRemindException;
import org.apache.shiro.biz.authc.exception.UnsupportedMethodException;
import org.apache.shiro.biz.utils.SubjectUtils;
import org.apache.shiro.biz.utils.WebUtils;
import org.springframework.context.NoSuchMessageException;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;

import com.alibaba.fastjson.JSONObject;

/**
 * Post认证请求失败后的处理实现
 */
public class DefaultAuthenticationFailureHandler  implements AuthenticationFailureHandler {

	protected MessageSourceAccessor messages = ShiroBizMessageSource.getAccessor();
	 
	@Override
	public boolean supports(AuthenticationException e) {
		return SubjectUtils.supports(e.getClass(), UnsupportedMethodException.class,
				NoneCaptchaException.class, IncorrectCaptchaException.class);
	}

	@Override
	public void onAuthenticationFailure(AuthenticationToken token, ServletRequest request, ServletResponse response, AuthenticationException e) {
		
		try {
			
			HttpServletRequest httpRequest = WebUtils.toHttp(request);
			HttpServletResponse httpResponse = WebUtils.toHttp(response);
			
			httpResponse.setStatus(HttpStatus.UNAUTHORIZED.value());
			httpResponse.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
			
			if (e instanceof UnsupportedMethodException) {
				JSONObject.writeJSONString(response.getWriter(), AuthcResponse.error(AuthcResponseCode.SC_AUTHC_METHOD_NOT_ALLOWED.getCode(),
						messages.getMessage(AuthcResponseCode.SC_AUTHC_METHOD_NOT_ALLOWED.getMsgKey(), e.getMessage())));
			} else if (e instanceof OverRetryRemindException) {
					JSONObject.writeJSONString(response.getWriter(), AuthcResponse.error(AuthcResponseCode.SC_AUTHC_OVER_RETRY_REMIND.getCode(),
							messages.getMessage(AuthcResponseCode.SC_AUTHC_OVER_RETRY_REMIND.getMsgKey(), e.getMessage())));
			} else if (e instanceof CaptchaSendException) {
				JSONObject.writeJSONString(response.getWriter(), AuthcResponse.error(AuthcResponseCode.SC_AUTHC_CAPTCHA_SEND_FAIL.getCode(),
						messages.getMessage(AuthcResponseCode.SC_AUTHC_CAPTCHA_SEND_FAIL.getMsgKey(), e.getMessage())));
			} else if (e instanceof NoneCaptchaException) {
				JSONObject.writeJSONString(response.getWriter(), AuthcResponse.error(AuthcResponseCode.SC_AUTHC_CAPTCHA_REQUIRED.getCode(),
						messages.getMessage(AuthcResponseCode.SC_AUTHC_CAPTCHA_REQUIRED.getMsgKey(), e.getMessage())));
			} else if (e instanceof ExpiredCaptchaException) {
				JSONObject.writeJSONString(response.getWriter(), AuthcResponse.error(AuthcResponseCode.SC_AUTHC_CAPTCHA_EXPIRED.getCode(),
						messages.getMessage(AuthcResponseCode.SC_AUTHC_CAPTCHA_EXPIRED.getMsgKey(), e.getMessage())));
			} else if (e instanceof IncorrectCaptchaException) {
				JSONObject.writeJSONString(response.getWriter(), AuthcResponse.error(AuthcResponseCode.SC_AUTHC_CAPTCHA_INCORRECT.getCode(),
						messages.getMessage(AuthcResponseCode.SC_AUTHC_CAPTCHA_INCORRECT.getMsgKey(), e.getMessage())));
			} else if (e instanceof InvalidCaptchaException) {
				JSONObject.writeJSONString(response.getWriter(), AuthcResponse.error(AuthcResponseCode.SC_AUTHC_CAPTCHA_INVALID.getCode(),
						messages.getMessage(AuthcResponseCode.SC_AUTHC_CAPTCHA_INVALID.getMsgKey(), e.getMessage())));
			} else if (e instanceof NoneTokenException) {
				JSONObject.writeJSONString(response.getWriter(), AuthcResponse.error(AuthcResponseCode.SC_AUTHZ_TOKEN_REQUIRED.getCode(),
						messages.getMessage(AuthcResponseCode.SC_AUTHZ_TOKEN_REQUIRED.getMsgKey(), e.getMessage())));
			} else if (e instanceof ExpiredTokenException) {
				JSONObject.writeJSONString(response.getWriter(), AuthcResponse.error(AuthcResponseCode.SC_AUTHZ_TOKEN_EXPIRED.getCode(),
						messages.getMessage(AuthcResponseCode.SC_AUTHZ_TOKEN_EXPIRED.getMsgKey(), e.getMessage())));
			} else if (e instanceof IncorrectTokenException) {
				JSONObject.writeJSONString(response.getWriter(), AuthcResponse.error(AuthcResponseCode.SC_AUTHZ_TOKEN_INCORRECT.getCode(),
						messages.getMessage(AuthcResponseCode.SC_AUTHZ_TOKEN_INCORRECT.getMsgKey(), e.getMessage())));
			} else if (e instanceof InvalidTokenException) {
				JSONObject.writeJSONString(response.getWriter(), AuthcResponse.error(AuthcResponseCode.SC_AUTHZ_TOKEN_INVALID.getCode(),
						messages.getMessage(AuthcResponseCode.SC_AUTHZ_TOKEN_INVALID.getMsgKey(), e.getMessage())));
			} else {
				JSONObject.writeJSONString(response.getWriter(), AuthcResponse.error(AuthcResponseCode.SC_AUTHC_FAIL.getCode(),
						messages.getMessage(AuthcResponseCode.SC_AUTHC_FAIL.getMsgKey())));
			}
		} catch (NoSuchMessageException e1) {
			throw new AuthenticationException(e1);
		} catch (IOException e1) {
			throw new AuthenticationException(e1);
		}
		
	}

}
