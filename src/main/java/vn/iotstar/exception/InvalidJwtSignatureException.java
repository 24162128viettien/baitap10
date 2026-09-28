package vn.iotstar.exception;

/** Chữ ký không hợp lệ (thay cho io.jsonwebtoken.security.SignatureException). */
public class InvalidJwtSignatureException extends RuntimeException {
    private static final long serialVersionUID = 1L;
    public InvalidJwtSignatureException(String message) { super(message); }
}
