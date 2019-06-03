package org.apache.shiro.biz.web.filter.authc.listener;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.subject.Subject;

public interface LoginListener {

	void onSuccess(AuthenticationToken token, Subject subject, ServletRequest request, ServletResponse response);

	void onFailure(AuthenticationToken token, Exception ex, ServletRequest request, ServletResponse response);

}
