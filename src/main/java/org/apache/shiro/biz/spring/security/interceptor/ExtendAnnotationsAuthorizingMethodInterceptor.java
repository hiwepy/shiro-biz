package org.apache.shiro.biz.spring.security.interceptor;

import java.util.Collection;

import org.apache.shiro.authz.aop.AuthorizingAnnotationMethodInterceptor;
import org.apache.shiro.biz.authz.aop.RoleAllowsAnnotationMethodInterceptor;
import org.apache.shiro.spring.security.interceptor.AopAllianceAnnotationsAuthorizingMethodInterceptor;

public class ExtendAnnotationsAuthorizingMethodInterceptor extends AopAllianceAnnotationsAuthorizingMethodInterceptor {

	public ExtendAnnotationsAuthorizingMethodInterceptor() {
		super();
		
		Collection<AuthorizingAnnotationMethodInterceptor> interceptors = getMethodInterceptors();

		// 自定义
		interceptors.add(new RoleAllowsAnnotationMethodInterceptor());

		super.setMethodInterceptors(interceptors);
		
	}

}