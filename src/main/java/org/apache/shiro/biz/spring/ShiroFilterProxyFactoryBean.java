package org.apache.shiro.biz.spring;

import org.apache.shiro.biz.web.filter.HttpServletShiroFilter;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.filter.mgt.FilterChainManager;
import org.apache.shiro.web.filter.mgt.FilterChainResolver;
import org.apache.shiro.web.filter.mgt.PathMatchingFilterChainResolver;
import org.apache.shiro.web.mgt.WebSecurityManager;
import org.apache.shiro.web.servlet.AbstractShiroFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.BeanInitializationException;

public class ShiroFilterProxyFactoryBean extends ShiroFilterFactoryBean {
	
	private static transient final Logger log = LoggerFactory.getLogger(ShiroFilterProxyFactoryBean.class);

    /**
     * Whether or not to bind the constructed SecurityManager instance to static memory (via
     * SecurityUtils.setSecurityManager).  This was added to support https://issues.apache.org/jira/browse/SHIRO-287
     * @since 1.2
     */
    private boolean staticSecurityManagerEnabled;

	@Override
	protected AbstractShiroFilter createInstance() throws Exception {

        log.debug("Creating Shiro Filter instance.");

        SecurityManager securityManager = getSecurityManager();
        if (securityManager == null) {
            String msg = "SecurityManager property must be set.";
            throw new BeanInitializationException(msg);
        }

        if (!(securityManager instanceof WebSecurityManager)) {
            String msg = "The security manager does not implement the WebSecurityManager interface.";
            throw new BeanInitializationException(msg);
        }

        FilterChainManager manager = createFilterChainManager();

        //Expose the constructed FilterChainManager by first wrapping it in a
        // FilterChainResolver implementation. The AbstractShiroFilter implementations
        // do not know about FilterChainManagers - only resolvers:
        PathMatchingFilterChainResolver chainResolver = new PathMatchingFilterChainResolver();
        chainResolver.setFilterChainManager(manager);

        //Now create a concrete ShiroFilter instance and apply the acquired SecurityManager and built
        //FilterChainResolver.  It doesn't matter that the instance is an anonymous inner class
        //here - we're just using it because it is a concrete AbstractShiroFilter instance that accepts
        //injection of the SecurityManager and FilterChainResolver:
        SpringShiroFilterProxy shiroFilterProxy = new SpringShiroFilterProxy((WebSecurityManager) securityManager, chainResolver);
        shiroFilterProxy.setStaticSecurityManagerEnabled(staticSecurityManagerEnabled);
        return shiroFilterProxy;
    }
	
	 /**
     * Returns <code>{@link org.apache.shiro.web.servlet.AbstractShiroFilter}.class</code>
     *
     * @return <code>{@link org.apache.shiro.web.servlet.AbstractShiroFilter}.class</code>
     */
	@Override
    public Class getObjectType() {
        return SpringShiroFilterProxy.class;
    }

	
	/**
     * Ordinarily the {@code HttpServletShiroFilter} must be subclassed to additionally perform configuration
     * and initialization behavior.  Because this {@code FactoryBean} implementation manually builds the
     * {@link AbstractShiroFilter}'s
     * {@link AbstractShiroFilter#setSecurityManager(org.apache.shiro.web.mgt.WebSecurityManager) securityManager} and
     * {@link AbstractShiroFilter#setFilterChainResolver(org.apache.shiro.web.filter.mgt.FilterChainResolver) filterChainResolver}
     * properties, the only thing left to do is set those properties explicitly.  We do that in a simple
     * concrete subclass in the constructor.
     */
    private static final class SpringShiroFilterProxy extends HttpServletShiroFilter {
    	
        protected SpringShiroFilterProxy(WebSecurityManager webSecurityManager, FilterChainResolver resolver) {
            super();
            if (webSecurityManager == null) {
                throw new IllegalArgumentException("WebSecurityManager property cannot be null.");
            }
            setSecurityManager(webSecurityManager);
            if (resolver != null) {
                setFilterChainResolver(resolver);
            }
        }
    }
    
    public void setStaticSecurityManagerEnabled(boolean staticSecurityManagerEnabled) {
		this.staticSecurityManagerEnabled = staticSecurityManagerEnabled;
	}

}
