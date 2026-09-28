package vn.iotstar.exception;

public class InvalidJwtException extends RuntimeException {
    private static final long serialVersionUID = 1L;
    public InvalidJwtException(String message, Throwable cause) { super(message, cause); }
}
