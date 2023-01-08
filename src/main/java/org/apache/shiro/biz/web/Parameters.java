package org.apache.shiro.biz.web;

import org.apache.shiro.biz.utils.StringUtils;

import javax.servlet.FilterConfig;
import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import java.util.LinkedHashMap;
import java.util.Map;


public abstract class Parameters {
	
	static final String PARAMETER_SYSTEM_PREFIX = "shiro.";

	private static ServletConfig servletConfig;
	private static FilterConfig filterConfig;
	private static ServletContext servletContext;

	private Parameters() {
		super();
	}

	public static void initialize(ServletConfig config) {
		servletConfig = config;
		filterConfig = null;
		if (config != null) {
			final ServletContext context = config.getServletContext();
			initialize(context);
		}
	}
	
	public static void initialize(FilterConfig config) {
		filterConfig = config;
		servletConfig = null;
		if (config != null) {
			final ServletContext context = config.getServletContext();
			initialize(context);
		}
	}

	public static void initialize(ServletContext context) {
		servletContext = context;
	}

	public static ServletContext getServletContext() {
		assert servletContext != null;
		return servletContext;
	}

	/*
	 * 单个Boolean值解析
	 */
	public static boolean getBoolean(Parameter key,String def) {
		assert key != null;
		final String name = key.getCode();
		String para = getParameterByName(name);
		return Boolean.parseBoolean( para == null ? def : para);
	}
	
	/*
	 * 单个Int值解析
	 */
	public static int getInt(Parameter key,String def) {
		assert key != null;
		final String name = key.getCode();
		String para = getParameterByName(name);
		return Integer.parseInt(para == null ? def : para);
	}
	
	/*
	 * 单个Long值解析
	 */
	public static long getLong(Parameter key,String def) {
		assert key != null;
		final String name = key.getCode();
		String para = getParameterByName(name);
		return Long.parseLong(para == null ? def : para);
	}
	
	/*
	 * 单个String值解析
	 */
	public static String getString(Parameter key,String def) {
		assert key != null;
		final String name = key.getCode();
		String para = getParameterByName(name);
		return para == null ? def : para;
	}
	
	/*
	 * 单个String值解析
	 */
	public static String getString(Parameter key) {
		assert key != null;
		final String name = key.getCode();
		return getParameterByName(name);
	}

	/*
	 * 多个String值解析 ;多个配置可以用",; \t\n"中任意字符分割
	 */
	public static String[] getStringArray(Parameter key){
		assert key != null;
		final String name = key.getCode();
		String para = getParameterByName(name);
		return para == null ? new String[]{} : StringUtils.tokenizeToStringArray(para);
	}
	
	/*多个键值对解析*/
	public static Map<String, String[]> getStringMultiMap(Parameter key) {
        Map<String, String[]> result = new LinkedHashMap<String, String[]>();
        String[] entries = getStringArray(key);
        if (entries != null) {
            for (String entry : entries) {
            	if(StringUtils.isEmpty(entry)){
					continue;
				}
                String[] split = entry.split("=", 2);
                if (split.length == 2) {
                    String itemKey = split[0];
                    String[] itemValue = split[1].split("\\|");
                    result.put(itemKey, itemValue);
                }
            }
        }
        return result;
    }

	public static String getParameterByName(String parameterName) {
		assert parameterName != null;
		final String globalName = PARAMETER_SYSTEM_PREFIX + parameterName;
		String result = System.getProperty(globalName);
		if (result != null) {
			return result;
		}
		if (servletContext != null) {
			result = servletContext.getInitParameter(globalName);
			if (result != null) {
				return result;
			}
			// In a ServletContextListener, it's also possible to call servletContext.setAttribute("http.xxx", "true"); for example
			final Object attribute = servletContext.getAttribute(globalName);
			if (attribute instanceof String) {
				return (String) attribute;
			}
		}
		if (filterConfig != null) {
			result = filterConfig.getInitParameter(parameterName);
			if (result != null) {
				return result;
			}
		}
		if (servletConfig != null) {
			result = servletConfig.getInitParameter(parameterName);
			if (result != null) {
				return result;
			}
		}
		return null;
	}
	
}
