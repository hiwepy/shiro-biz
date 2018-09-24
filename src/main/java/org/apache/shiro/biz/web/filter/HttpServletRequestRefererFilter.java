package org.apache.shiro.biz.web.filter;

import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.shiro.biz.utils.WebUtils;
import org.apache.shiro.web.filter.AccessControlFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.PathMatcher;
import org.springframework.util.StringUtils;


public class HttpServletRequestRefererFilter extends AccessControlFilter {

	protected Logger LOG = LoggerFactory.getLogger(getClass());
	protected PathMatcher matcher = new AntPathMatcher();
	/** Specifies the name of the Header on where to find the referer (i.e. Referer). */
	private String refererHeaderName = "Referer";
	/**
	 * Allowed access referrer of the application
	 */
	protected Set<String> allowedReferers = Collections.emptySet();
	/**
	 * Allowed access URI for each referrer
	 */
	private Map<String /* URI Pattern */, String /* Referer */> allowedAccessURIMap = new LinkedHashMap<String, String>();
	
	@Override
	protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue)
			throws Exception {
		//请求的request对象
		HttpServletRequest httpRequest = WebUtils.toHttp(request);
		//获取请求访问来源；referer为客户端带来的请求头 
		String referer = httpRequest.getHeader(getRefererHeaderName());
		/*  request.getHeader("Referer")获取来访者地址。
			只有通过链接访问当前页的时候，才能获取上一页的地址；否则request.getHeader("Referer")的值为Null，
			通过window.open打开当前页或者直接输入地址，也为Null。
		*/
		//来源为空
		if(StringUtils.isEmpty(referer)){
			return false;
		}
		if ( !allowedReferers.isEmpty() && containsItem(allowedReferers, referer )) {
			return true;
		}
		
		Iterator<Entry<String, String>> ite = allowedAccessURIMap.entrySet().iterator();
		while (ite.hasNext()) {
			Entry<String, String> entry = ite.next();
			if(matcher.match(entry.getKey(), httpRequest.getRequestURI()) &&
				matcher.match(entry.getValue(), referer)) {
				return true;
			}
		}
		if(LOG.isDebugEnabled()){
			LOG.debug("Not Allowed Access Referrer : {}.", referer );
		}
		return false;
	}
	
	@Override
	protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
		String mString = String.format("Request Denied! Request Referer {%s} is Not Allowed.", WebUtils.toHttp(request).getHeader(getRefererHeaderName()));
		//判断是否ajax请求
		if( WebUtils.isAjaxRequest(request) ){ 
			WebUtils.writeJSONString(response, HttpServletResponse.SC_FORBIDDEN, mString);
		} else {
			WebUtils.toHttp(response).sendError(HttpServletResponse.SC_FORBIDDEN, mString);
		}
		// The request has been processed, no longer enter the next filter
		return false;
	}

	/**
     * @param itemCollection - Collection of string items (all lowercase).
     * @param item           - Item to search for.
     * @return true if itemCollection contains the item, false otherwise.
     */
    private boolean containsItem(Collection<String> itemCollection, String item) {
        for (String pattern : itemCollection) {
            if (matcher.match(pattern, item)){
                return true;
            }
        }
        return false;
    }

	public String getRefererHeaderName() {
		return refererHeaderName;
	}

	public void setRefererHeaderName(String refererHeaderName) {
		this.refererHeaderName = refererHeaderName;
	}
	
	/**
     * Sets the allowed Referer
     * @param allowedReferers A comma-delimited list of Referers
     */
    public void setAllowedReferers(String allowedReferers) {
    	this.allowedReferers = StringUtils.commaDelimitedListToSet(allowedReferers);
    }

	public Set<String> getAllowedReferers() {
		return allowedReferers;
	}

	public void setAllowedReferers(Set<String> allowedReferers) {
		this.allowedReferers = allowedReferers;
	}

	public Map<String, String> getAllowedAccessURIMap() {
		return allowedAccessURIMap;
	}

	public void setAllowedAccessURIMap(Map<String, String> allowedAccessURIMap) {
		this.allowedAccessURIMap = allowedAccessURIMap;
	}
	
}
