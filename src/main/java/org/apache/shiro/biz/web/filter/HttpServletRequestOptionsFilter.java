package org.apache.shiro.biz.web.filter;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;

import org.apache.shiro.biz.utils.StringUtils;
import org.apache.shiro.biz.utils.WebUtils;
import org.apache.shiro.web.filter.AccessControlFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 
 * @author <a href="https://github.com/vindell">vindell</a>
 * https://developer.mozilla.org/zh-CN/docs/Web/HTTP/X-Frame-Options <br/>
 * https://developer.mozilla.org/zh-CN/docs/Web/HTTP/Headers/X-Content-Type-Options
 */
public class HttpServletRequestOptionsFilter extends AccessControlFilter {
	
	private static final Logger LOG = LoggerFactory.getLogger(HttpServletRequestOptionsFilter.class);
	public static final String DEFAULT_X_FRAME_OPTIONS = "SAMEORIGIN";
	public static final String DEFAULT_X_CONTENT_TYPE_OPTIONS = "nosniff";
	
	protected String XFrameOptions = DEFAULT_X_FRAME_OPTIONS;
	protected String XContentTypeOptions = DEFAULT_X_CONTENT_TYPE_OPTIONS;
	
	@Override
	protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue)
			throws Exception {
		
		HttpServletResponse httpResponse = WebUtils.toHttp(response);
		
		String xFrameOptions = StringUtils.hasText(getXFrameOptions()) ?  getXFrameOptions() :  DEFAULT_X_FRAME_OPTIONS;
		String xContentTypeOptions =  StringUtils.hasText(getXContentTypeOptions()) ? getXContentTypeOptions() : DEFAULT_X_CONTENT_TYPE_OPTIONS;
		
		//iframe策略
		httpResponse.setHeader("X-Frame-Options", xFrameOptions);
		//防止在IE9、chrome和safari中的MIME类型混淆攻击
		httpResponse.setHeader("X-Content-Type-Options", xContentTypeOptions);
		
		if(LOG.isDebugEnabled()){
			LOG.debug("Filter:{} Set HTTP HEADER: X-Frame-Options:{}; X-Content-Type-Options:{}.",  getName(), xFrameOptions, xContentTypeOptions );
		}
		
		return true;
	}


	@Override
	protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
		return true;
	}


	public String getXFrameOptions() {
		return XFrameOptions;
	}

	public void setXFrameOptions(String xFrameOptions) {
		XFrameOptions = xFrameOptions;
	}

	public String getXContentTypeOptions() {
		return XContentTypeOptions;
	}

	public void setXContentTypeOptions(String xContentTypeOptions) {
		XContentTypeOptions = xContentTypeOptions;
	}
	
	
}
