package org.inlighting.controller;

import org.apache.shiro.ShiroException;
import org.inlighting.bean.ResponseBean;
import org.inlighting.exception.UnauthorizedException;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

@RestControllerAdvice
public class ExceptionController {

    // 捕捉shiro的异常
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    @ExceptionHandler(ShiroException.class)
    public ResponseBean handle401(ShiroException e) {
        return new ResponseBean(401, e.getMessage(), null);
    }

    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler(Exception.class)
    public ResponseBean handle400() {
        return new ResponseBean(400, "Error", null);
    }
}

