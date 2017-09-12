package org.apache.shiro.biz.web.servlet;

import java.io.IOException;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.ExcessiveAttemptsException;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.LockedAccountException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.biz.web.Parameters;
import org.apache.shiro.subject.Subject;

/**
 * <p>User: Zhang Kaitao
 * <p>Date: 14-1-29
 * <p>Version: 1.0
 */
@WebServlet(name = "loginServlet", urlPatterns = "/login")
public class ShiroHttpLoginServlet extends AbstractHttpServlet {

	protected String redirectURL = "";
	protected String dispatchURL = "";
	
	@Override
	public void init(ServletConfig filterConfig) throws ServletException {
		super.init(filterConfig);
	}
	
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        req.getRequestDispatcher("/WEB-INF/jsp/login.jsp").forward(req, resp);
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
    	//每次请求到达，必须调用一次初始化方法，否则可能取得的参数是其他Servlet的参数（如同一个Servlet有多个配置情况下就会出现参数干扰问题）
    	Parameters.initialize(getServletConfig());
    	
    	String error = null;
        String username = req.getParameter("username");
        String password = req.getParameter("password");
        Subject subject = SecurityUtils.getSubject();
        try {
        	UsernamePasswordToken token = new UsernamePasswordToken(username, password);
        	token.setRememberMe(true);
            subject.login(token);
	    } catch ( UnknownAccountException uae ) { //用户名未知...  
	    	error = "用户名/密码错误";
	    } catch ( IncorrectCredentialsException ice ) {//凭据不正确，例如密码不正确 ...  
	    	error = "用户名/密码错误";
	    } catch ( LockedAccountException lae ) { //用户被锁定，例如管理员把某个用户禁用...  
	    } catch ( ExcessiveAttemptsException eae ) {//尝试认证次数多余系统指定次数 ...  
	    } catch ( AuthenticationException ae ) {  
	    	//其他未指定异常  
	    	//其他错误，比如锁定，如果想单独处理请单独catch处理
            error = "其他错误：" + ae.getMessage();
	    }  
	    
        //未抛出异常，程序正常向下执行
    

        if(error != null) {//出错了，返回登录页面
            req.setAttribute("error", error);
            req.getRequestDispatcher("/WEB-INF/jsp/login.jsp").forward(req, resp);
        } else {//登录成功
            req.getRequestDispatcher("/WEB-INF/jsp/loginSuccess.jsp").forward(req, resp);
        }
    }
}
