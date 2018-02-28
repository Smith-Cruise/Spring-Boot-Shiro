package org.inlighting.controller;

import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authz.annotation.*;
import org.apache.shiro.subject.Subject;
import org.inlighting.bean.ResponseBean;
import org.inlighting.database.UserService;
import org.inlighting.database.UserBean;
import org.inlighting.exception.UnauthorizedException;
import org.inlighting.util.JWTUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

@RestController
public class WebController {

    private static final Logger LOGGER = LogManager.getLogger(WebController.class);

    private UserService userService;

    @Autowired
    public void setService(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/login")
    public ResponseBean login(@RequestParam("username") String username,
                              @RequestParam("password") String password) {
        UserBean userBean = userService.getUser(username);
        if (userBean.getPassword().equals(password)) {
            return new ResponseBean(200, "Login success", JWTUtil.sign(username, password));
        } else {
            throw new UnauthorizedException();
        }
    }

    @GetMapping("/article")
    public ResponseBean article() {
        Subject subject = SecurityUtils.getSubject();
        if (subject.isAuthenticated()) {
            return new ResponseBean(200, "You are already logged in", null);
        } else {
            return new ResponseBean(200, "You are guest", null);
        }
    }

    @GetMapping("/require_auth")
    @RequiresAuthentication
    public ResponseBean requireAuth() {
        return new ResponseBean(200, "You are authenticated", null);
    }

    @GetMapping("/require_role")
    @RequiresRoles("admin")
    public ResponseBean requireRole() {
        return new ResponseBean(200, "You are visiting require_role", null);
    }

    @GetMapping("/require_permission")
    @RequiresPermissions(logical = Logical.AND, value = {"view", "edit"})
    public ResponseBean requirePermission() {
        return new ResponseBean(200, "You are visiting permission require edit,view", null);
    }

    @RequestMapping(path = "/401")
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public ResponseBean unauthorized() {
        return new ResponseBean(401, "Unauthorized", null);
    }
}
