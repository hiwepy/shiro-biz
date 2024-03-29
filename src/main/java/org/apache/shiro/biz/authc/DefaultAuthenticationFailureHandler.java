package org.apache.shiro.biz.authc;

import com.alibaba.fastjson2.JSON;
import org.apache.shiro.authc.*;
import org.apache.shiro.authc.pam.UnsupportedTokenException;
import org.apache.shiro.biz.ShiroBizMessageSource;
import org.apache.shiro.biz.authc.exception.*;
import org.apache.shiro.biz.utils.SubjectUtils;
import org.apache.shiro.biz.utils.WebUtils;
import org.apache.shiro.biz.web.servlet.http.HttpStatus;
import org.springframework.context.NoSuchMessageException;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.http.MediaType;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;


/**
 * Post认证请求失败后的处理实现
 */
public class DefaultAuthenticationFailureHandler implements AuthenticationFailureHandler {

	protected MessageSourceAccessor messages = ShiroBizMessageSource.getAccessor();

	@Override
	public boolean supports(AuthenticationException e) {
		return SubjectUtils.isAssignableFrom(e.getClass(), CaptchaSendException.class, DisabledAccountException.class,
				LockedAccountException.class, ExcessiveAttemptsException.class, ExpiredCaptchaException.class,
				ExpiredCredentialsException.class, ExpiredTicketException.class, ExpiredTokenException.class,
				IncorrectCaptchaException.class, IncorrectCredentialsException.class, IncorrectSecretException.class,
				IncorrectTicketException.class, IncorrectTokenException.class, InvalidAccountException.class,
				NoneCaptchaException.class, NoneRoleException.class, NoneTicketException.class,
				NoneTokenException.class, SessionKickedoutException.class, SessionRestrictedException.class,
				TerminalRestrictedException.class, SessionKickedoutException.class, UnknownAccountException.class,
				UnsupportedMethodException.class, UnsupportedTokenException.class);
	}

	@Override
	public void onAuthenticationFailure(AuthenticationToken token, ServletRequest request, ServletResponse response,
			AuthenticationException e) {

		try {

			WebUtils.toHttp(response).setStatus(HttpStatus.SC_OK);
			response.setContentType(MediaType.APPLICATION_JSON_VALUE);
			response.setCharacterEncoding(StandardCharsets.UTF_8.toString());

			if (e instanceof CaptchaSendException) {
				JSON.writeTo(response.getOutputStream(), AuthcResponse.error(
						AuthcResponseCode.SC_AUTHC_CAPTCHA_SEND_FAIL.getCode(),
						messages.getMessage(AuthcResponseCode.SC_AUTHC_CAPTCHA_SEND_FAIL.getMsgKey(), e.getMessage())));
			} else if (e instanceof DisabledAccountException) {
				JSON.writeTo(response.getOutputStream(), AuthcResponse.error(
						AuthcResponseCode.SC_AUTHC_USER_DISABLED.getCode(),
						messages.getMessage(AuthcResponseCode.SC_AUTHC_USER_DISABLED.getMsgKey(), e.getMessage())));
			} else if (e instanceof LockedAccountException) {
				JSON.writeTo(response.getOutputStream(), AuthcResponse.error(
						AuthcResponseCode.SC_AUTHC_USER_LOCKED.getCode(),
						messages.getMessage(AuthcResponseCode.SC_AUTHC_USER_LOCKED.getMsgKey(), e.getMessage())));
			} else if (e instanceof ExcessiveAttemptsException) {
				JSON.writeTo(response.getOutputStream(),
						AuthcResponse.error(AuthcResponseCode.SC_AUTHC_EXCESSIVE_ATTEMPTS.getCode(),
								messages.getMessage(AuthcResponseCode.SC_AUTHC_EXCESSIVE_ATTEMPTS.getMsgKey(),
										e.getMessage())));
			} else if (e instanceof ExpiredCaptchaException) {
				JSON.writeTo(response.getOutputStream(), AuthcResponse.error(
						AuthcResponseCode.SC_AUTHC_CAPTCHA_EXPIRED.getCode(),
						messages.getMessage(AuthcResponseCode.SC_AUTHC_CAPTCHA_EXPIRED.getMsgKey(), e.getMessage())));
			} else if (e instanceof ExpiredCredentialsException) {
				JSON.writeTo(response.getOutputStream(),
						AuthcResponse.error(AuthcResponseCode.SC_AUTHC_CREDENTIALS_INCORRECT.getCode(),
								messages.getMessage(AuthcResponseCode.SC_AUTHC_CREDENTIALS_INCORRECT.getMsgKey(),
										e.getMessage())));
			} else if (e instanceof ExpiredTicketException) {
				JSON.writeTo(response.getOutputStream(), AuthcResponse.error(
						AuthcResponseCode.SC_AUTHZ_TICKET_EXPIRED.getCode(),
						messages.getMessage(AuthcResponseCode.SC_AUTHZ_TICKET_EXPIRED.getMsgKey(), e.getMessage())));
			} else if (e instanceof ExpiredTokenException) {
				JSON.writeTo(response.getOutputStream(), AuthcResponse.error(
						AuthcResponseCode.SC_AUTHZ_TOKEN_EXPIRED.getCode(),
						messages.getMessage(AuthcResponseCode.SC_AUTHZ_TOKEN_EXPIRED.getMsgKey(), e.getMessage())));
			} else if (e instanceof IncorrectCaptchaException) {
				JSON.writeTo(response.getOutputStream(), AuthcResponse.error(
						AuthcResponseCode.SC_AUTHC_CAPTCHA_INCORRECT.getCode(),
						messages.getMessage(AuthcResponseCode.SC_AUTHC_CAPTCHA_INCORRECT.getMsgKey(), e.getMessage())));
			} else if (e instanceof IncorrectCredentialsException) {
				JSON.writeTo(response.getOutputStream(), AuthcResponse.error(
						AuthcResponseCode.SC_AUTHC_CAPTCHA_INCORRECT.getCode(),
						messages.getMessage(AuthcResponseCode.SC_AUTHC_CAPTCHA_INCORRECT.getMsgKey(), e.getMessage())));
			} else if (e instanceof IncorrectSecretException) {
				JSON.writeTo(response.getOutputStream(),
						AuthcResponse.error(AuthcResponseCode.SC_AUTHC_CREDENTIALS_INCORRECT.getCode(),
								messages.getMessage(AuthcResponseCode.SC_AUTHC_CREDENTIALS_INCORRECT.getMsgKey(),
										e.getMessage())));
			} else if (e instanceof IncorrectTicketException) {
				JSON.writeTo(response.getOutputStream(), AuthcResponse.error(
						AuthcResponseCode.SC_AUTHZ_TICKET_INCORRECT.getCode(),
						messages.getMessage(AuthcResponseCode.SC_AUTHZ_TICKET_INCORRECT.getMsgKey(), e.getMessage())));
			} else if (e instanceof IncorrectTokenException) {
				JSON.writeTo(response.getOutputStream(), AuthcResponse.error(
						AuthcResponseCode.SC_AUTHZ_TOKEN_INCORRECT.getCode(),
						messages.getMessage(AuthcResponseCode.SC_AUTHZ_TOKEN_INCORRECT.getMsgKey(), e.getMessage())));
			} else if (e instanceof InvalidAccountException) {
				JSON.writeTo(response.getOutputStream(),
						AuthcResponse.error(AuthcResponseCode.SC_AUTHC_CREDENTIALS_INCORRECT.getCode(),
								messages.getMessage(AuthcResponseCode.SC_AUTHC_CREDENTIALS_INCORRECT.getMsgKey(),
										e.getMessage())));
			} else if (e instanceof InvalidCaptchaException) {
				JSON.writeTo(response.getOutputStream(), AuthcResponse.error(
						AuthcResponseCode.SC_AUTHC_CAPTCHA_INVALID.getCode(),
						messages.getMessage(AuthcResponseCode.SC_AUTHC_CAPTCHA_INVALID.getMsgKey(), e.getMessage())));
			} else if (e instanceof InvalidStateException) {
				JSON.writeTo(response.getOutputStream(), AuthcResponse.error(
						AuthcResponseCode.SC_AUTHC_CAPTCHA_INVALID.getCode(),
						messages.getMessage(AuthcResponseCode.SC_AUTHC_CAPTCHA_INVALID.getMsgKey(), e.getMessage())));
			} else if (e instanceof InvalidTicketException) {
				JSON.writeTo(response.getOutputStream(), AuthcResponse.error(
						AuthcResponseCode.SC_AUTHZ_TICKET_INVALID.getCode(),
						messages.getMessage(AuthcResponseCode.SC_AUTHZ_TICKET_INVALID.getMsgKey(), e.getMessage())));
			} else if (e instanceof InvalidTokenException) {
				JSON.writeTo(response.getOutputStream(), AuthcResponse.error(
						AuthcResponseCode.SC_AUTHZ_TOKEN_INVALID.getCode(),
						messages.getMessage(AuthcResponseCode.SC_AUTHZ_TOKEN_INVALID.getMsgKey(), e.getMessage())));
			} else if (e instanceof NoneCaptchaException) {

				// 已经超出了重试限制，需要进行提醒

				JSON.writeTo(response.getOutputStream(), AuthcResponse.error(
						AuthcResponseCode.SC_AUTHC_CAPTCHA_REQUIRED.getCode(),
						messages.getMessage(AuthcResponseCode.SC_AUTHC_CAPTCHA_REQUIRED.getMsgKey(), e.getMessage())));
			} else if (e instanceof NoneRoleException) {
				JSON.writeTo(response.getOutputStream(), AuthcResponse.error(
						AuthcResponseCode.SC_AUTHC_USER_NO_ROLE.getCode(),
						messages.getMessage(AuthcResponseCode.SC_AUTHC_USER_NO_ROLE.getMsgKey(), e.getMessage())));
			} else if (e instanceof NoneTicketException) {
				JSON.writeTo(response.getOutputStream(), AuthcResponse.error(
						AuthcResponseCode.SC_AUTHZ_TICKET_REQUIRED.getCode(),
						messages.getMessage(AuthcResponseCode.SC_AUTHZ_TICKET_REQUIRED.getMsgKey(), e.getMessage())));
			} else if (e instanceof NoneTokenException) {
				JSON.writeTo(response.getOutputStream(), AuthcResponse.error(
						AuthcResponseCode.SC_AUTHZ_TOKEN_REQUIRED.getCode(),
						messages.getMessage(AuthcResponseCode.SC_AUTHZ_TOKEN_REQUIRED.getMsgKey(), e.getMessage())));
			} else if (e instanceof SessionKickedoutException) {
				JSON.writeTo(response.getOutputStream(), AuthcResponse.error(
						AuthcResponseCode.SC_AUTHC_SESSION_KICKEDOUT.getCode(),
						messages.getMessage(AuthcResponseCode.SC_AUTHC_SESSION_KICKEDOUT.getMsgKey(), e.getMessage())));
			} else if (e instanceof SessionRestrictedException) {
				JSON.writeTo(response.getOutputStream(),
						AuthcResponse.error(AuthcResponseCode.SC_AUTHC_SESSION_RESTRICTED.getCode(),
								messages.getMessage(AuthcResponseCode.SC_AUTHC_SESSION_RESTRICTED.getMsgKey(),
										e.getMessage())));
			} else if (e instanceof TerminalRestrictedException) {
				JSON.writeTo(response.getOutputStream(),
						AuthcResponse.error(AuthcResponseCode.SC_AUTHC_SESSION_TERMINAL_RESTRICTED.getCode(),
								messages.getMessage(AuthcResponseCode.SC_AUTHC_SESSION_TERMINAL_RESTRICTED.getMsgKey(),
										e.getMessage())));
			} else if (e instanceof UnknownAccountException) {
				JSON.writeTo(response.getOutputStream(), AuthcResponse.error(
						AuthcResponseCode.SC_AUTHC_USER_NOT_FOUND.getCode(),
						messages.getMessage(AuthcResponseCode.SC_AUTHC_USER_NOT_FOUND.getMsgKey(), e.getMessage())));
			} else if (e instanceof UnsupportedMethodException) {
				JSON.writeTo(response.getOutputStream(),
						AuthcResponse.error(AuthcResponseCode.SC_AUTHC_METHOD_NOT_ALLOWED.getCode(),
								messages.getMessage(AuthcResponseCode.SC_AUTHC_METHOD_NOT_ALLOWED.getMsgKey(),
										e.getMessage())));
			} else if (e instanceof UnsupportedTokenException) {
				JSON.writeTo(response.getOutputStream(),
						AuthcResponse.error(AuthcResponseCode.SC_AUTHC_METHOD_NOT_ALLOWED.getCode(),
								messages.getMessage(AuthcResponseCode.SC_AUTHC_METHOD_NOT_ALLOWED.getMsgKey(),
										e.getMessage())));
			} else {
				JSON.writeTo(response.getOutputStream(),
						AuthcResponse.error(AuthcResponseCode.SC_AUTHC_FAIL.getCode(),
								messages.getMessage(AuthcResponseCode.SC_AUTHC_FAIL.getMsgKey())));
			}

		} catch (NoSuchMessageException e1) {
			throw new AuthenticationException(e1);
		} catch (IOException e1) {
			throw new AuthenticationException(e1);
		}

	}

	@Override
	public int getOrder() {
		return Integer.MAX_VALUE;
	}

}
