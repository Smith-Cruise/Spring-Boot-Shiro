package org.inlighting.exception;

public class ErrorException extends RuntimeException {
    public ErrorException() {
        super();
    }

    public ErrorException(String msg) {
        super(msg);
    }
}
