package vn.iotstar.exception;

public class InvalidJwtSignatureException extends RuntimeException {
    private static final long serialVersionUID = 1L;
    public InvalidJwtSignatureException(String message) { super(message); }
}
