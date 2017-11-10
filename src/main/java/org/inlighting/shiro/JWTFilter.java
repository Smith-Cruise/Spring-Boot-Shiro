package org.inlighting.shiro;

import org.apache.shiro.web.filter.authc.BasicHttpAuthenticationFilter;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class JWTFilter extends BasicHttpAuthenticationFilter {

    @Override
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        // 获取Authorization字段
        String authorization = httpServletRequest.getHeader("Authorization");
        if (authorization!=null) {
            try {
                JWTToken token = new JWTToken(authorization);
                // 提交给realm进行登入，如果错误他会抛出异常并被捕获
                getSubject(request, response).login(token);
                return true;
            } catch (Exception e) {
                response401(request, response);
                return false;
            }
        } else {
            response401(request, response);
            return false;
        }
    }

    /**
     * 将请求返回到 /401
     */
    private void response401(ServletRequest req, ServletResponse resp) throws Exception {
        HttpServletResponse httpServletResponse = (HttpServletResponse) resp;
        httpServletResponse.sendRedirect("/401");
    }
}
