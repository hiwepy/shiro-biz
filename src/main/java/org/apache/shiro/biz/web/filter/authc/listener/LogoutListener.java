package org.apache.shiro.biz.web.filter.authc.listener;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.apache.shiro.subject.Subject;

public interface LogoutListener {

	void beforeLogout(Subject subject, ServletRequest request, ServletResponse response);

	void onFailure(Subject subject, Exception ex);

	void onSuccess(Subject subject, ServletRequest request, ServletResponse response);

}
