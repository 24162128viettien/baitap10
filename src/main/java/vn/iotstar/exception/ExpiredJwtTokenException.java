package vn.iotstar.exception;

/** Token hết hạn (thay cho io.jsonwebtoken.ExpiredJwtException). */
public class ExpiredJwtTokenException extends RuntimeException {
    private static final long serialVersionUID = 1L;
    public ExpiredJwtTokenException(String message) { super(message); }
}
