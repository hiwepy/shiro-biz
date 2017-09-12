package org.apache.shiro.biz.spring.security.interceptor;

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;

import org.apache.shiro.authz.annotation.RequiresAuthentication;
import org.apache.shiro.authz.annotation.RequiresGuest;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.apache.shiro.authz.annotation.RequiresUser;
import org.apache.shiro.biz.authz.annotation.RolesAllowed;
import org.apache.shiro.spring.security.interceptor.AuthorizationAttributeSourceAdvisor;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 * 自定义的注解权限AOP扫描
 * 
 * @author zhihua
 *         <p>
 *         http://blog.csdn.net/mingtian625/article/details/46996033
 *         </p>
 * 
 *         <pre>
 * 
 * 	&lt;bean id="lifecycleBeanPostProcessor" class="org.apache.shiro.spring.LifecycleBeanPostProcessor" /&gt;
 * 
 *  <!-- Enable Shiro Annotations for Spring-configured beans.  Only run after -->  
 *	<!-- the lifecycleBeanProcessor has run: -->  
 *	&lt;bean class="org.springframework.aop.framework.autoproxy.DefaultAdvisorAutoProxyCreator" depends-on="lifecycleBeanPostProcessor"/&gt;
 *	<!-- 这个是原生的，因为不满足需要，所以修改为自定义的了 -->  
 *	<!-- &lt;bean class="org.apache.shiro.spring.security.interceptor.AuthorizationAttributeSourceAdvisor"&gt;
 *	    &lt;property name="securityManager" ref="securityManager"/&gt;
 *		&lt;property name="classFilter" ref="annotationClassFilter" /&gt;
 *	&lt;/bean&gt; -->  
 *	&lt;bean class="org.apache.shiro.spring.security.interceptor.ZFAuthorizationAttributeSourceAdvisor"&gt;
 *	    &lt;property name="securityManager" ref="securityManager"/&gt;
 *		&lt;property name="classFilter" ref="annotationClassFilter" /&gt;
 *	&lt;/bean&gt;
 * </pre>
 */
@SuppressWarnings({ "unchecked", "serial", "rawtypes" })
public class ZFAuthorizationAttributeSourceAdvisor extends AuthorizationAttributeSourceAdvisor {

	// 权限注解
	private static final Class<? extends Annotation>[] AUTHZ_ANNOTATION_CLASSES = new Class[] { RolesAllowed.class,
			RequiresPermissions.class, RequiresRoles.class, RequiresUser.class, RequiresGuest.class,
			RequiresAuthentication.class };

	// web注解
	private static final Class<? extends Annotation>[] WEB_ANNOTATION_CLASSES = new Class[] { RequestMapping.class };

	/**
	 * Create a new AuthorizationAttributeSourceAdvisor.
	 */
	public ZFAuthorizationAttributeSourceAdvisor() {
		setAdvice(new ZFAnnotationsAuthorizingMethodInterceptor());
	}

	/**
	 * 匹配带有注解的方法
	 */
	@Override
	public boolean matches(Method method, Class targetClass) {
		// 检查方法上是否有权限注解
		boolean flag = super.matches(method, targetClass);
		// 如果方法上没有权限注解，尝试获取类上的默认权限注解
		if (!flag && isAuthzAnnotationPresent(targetClass) && isWebAnnotationPresent(method)) {
			flag = true;
		}
		return flag;
	}

	/**
	 * 查看Controller类是否有权限注解
	 * 
	 * @param clazz
	 * @return
	 */
	private boolean isAuthzAnnotationPresent(Class clazz) {
		for (Class<? extends Annotation> annClass : AUTHZ_ANNOTATION_CLASSES) {
			Annotation a = AnnotationUtils.findAnnotation(clazz, annClass);
			if (a != null) {
				return true;
			}
		}
		return false;
	}

	/**
	 * 查看方法是否有web注解，是否是一个rest接口
	 * 
	 * @param method
	 * @return
	 */
	private boolean isWebAnnotationPresent(Method method) {
		for (Class<? extends Annotation> annClass : WEB_ANNOTATION_CLASSES) {
			Annotation a = AnnotationUtils.findAnnotation(method, annClass);
			if (a != null) {
				return true;
			}
		}
		return false;
	}

}