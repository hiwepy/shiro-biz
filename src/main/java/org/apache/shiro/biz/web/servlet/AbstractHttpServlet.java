package org.apache.shiro.biz.web.servlet;

import java.io.IOException;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.shiro.biz.web.Parameters;

/**
 * 基础HttpServlet
 * @author <a href="https://github.com/hiwepy">hiwepy</a>
 */
@SuppressWarnings("serial")
public abstract class AbstractHttpServlet extends HttpServlet {

	@Override
	public void init(ServletConfig config) throws ServletException {
		super.init(config);
		// 初始化参数取值对象
		Parameters.initialize(config);
	}
	
	protected void doGet(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {
		doPost(request, response);
	}

	@Override
	protected void doDelete(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {

	}

	@Override
	protected void doHead(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {

	}

	@Override
	protected void doOptions(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {

	}

	@Override
	protected void doPut(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {

	}

	@Override
	protected void doTrace(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {

	}

}
