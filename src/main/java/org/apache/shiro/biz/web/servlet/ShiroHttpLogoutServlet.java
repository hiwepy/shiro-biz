package org.apache.shiro.biz.web.servlet;

import java.io.IOException;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.biz.web.Parameter;
import org.apache.shiro.biz.web.Parameters;
import org.apache.shiro.util.StringUtils;

/**
 * 
 * @className	： ShiroHttpLogoutServlet
 * @description	： TODO(描述这个类的作用)
 * @author 		： <a href="https://github.com/vindell">vindell</a>
 * @date		： 2017年9月12日 下午10:49:13
 * @version 	V1.0
 */
@SuppressWarnings("serial")
@WebServlet(name = "logoutServlet", urlPatterns = "/logout")
public class ShiroHttpLogoutServlet extends AbstractHttpServlet {

	protected String redirectURL = "";
	protected String dispatchURL = "";

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
    	//每次请求到达，必须调用一次初始化方法，否则可能取得的参数是其他Servlet的参数（如同一个Servlet有多个配置情况下就会出现参数干扰问题）
    	Parameters.initialize(getServletConfig());
    	
    	redirectURL = Parameters.getString(Parameter.LOGIN_TYPE_KEY);
		dispatchURL = Parameters.getString(Parameter.LOGIN_TYPE_KEY);
		
    	//Session对象
    	HttpSession session = req.getSession();
        //登录成功;记录登录方式标记；1：页面登录；2：单点登录；3：票据登录（通过握手秘钥等参数认证登录）
        String loginType = (String) session.getAttribute(Parameters.getString(Parameter.LOGIN_TYPE_KEY));
      /*  //当前登录账户
      	UserModel loginUser =  (UserModel) session.getAttribute(Parameters.getString(Parameter.SESSION_USER_KEY));
        //用户没有登录过
      	if(null == loginUser){
      		//内部登录
      		if( LoginType.INNER.getKey().equals(loginType.getKey()) ){
      			//跳转到系统登录页面
      			req.getRequestDispatcher(dispatchURL).forward(req, resp);
            }
      		//外部登录：重定向到外部登录入口
      		else{
            	resp.sendRedirect(redirectURL);
            }
        }
        //用户已经登录
      	else{
      		//Shiro回话登出
      		SecurityUtils.getSubject().logout();
      		//内部登录
      		if( LoginType.INNER.getKey().equals(loginType.getKey()) ){
      			//跳转到系统登录页面
      			req.getRequestDispatcher(dispatchURL).forward(req, resp);
            }
      		//外部登录：重定向到外部登录入口
      		else{
            	resp.sendRedirect(redirectURL);
            }
      	}*/
    }

}
