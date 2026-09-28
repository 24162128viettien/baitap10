package vn.iotstar.exception;

/** Token sai định dạng (không parse được). */
public class InvalidJwtException extends RuntimeException {
    private static final long serialVersionUID = 1L;
    public InvalidJwtException(String message, Throwable cause) { super(message, cause); }
}
