package vn.iotstar.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AccountStatusException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(BadCredentialsException.class)
    public ProblemDetail handleBadCredentials(BadCredentialsException ex) {
        return build(HttpStatus.UNAUTHORIZED, ex.getMessage(), "The username or password is incorrect");
    }

    @ExceptionHandler(AccountStatusException.class)
    public ProblemDetail handleAccountStatus(AccountStatusException ex) {
        return build(HttpStatus.FORBIDDEN, ex.getMessage(), "The account is locked");
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ProblemDetail handleAccessDenied(AccessDeniedException ex) {
        return build(HttpStatus.FORBIDDEN, ex.getMessage(), "You are not authorized to access this resource");
    }

    @ExceptionHandler(InvalidJwtSignatureException.class)
    public ProblemDetail handleSignature(InvalidJwtSignatureException ex) {
        return build(HttpStatus.UNAUTHORIZED, ex.getMessage(), "The JWT signature is invalid");
    }

    @ExceptionHandler(ExpiredJwtTokenException.class)
    public ProblemDetail handleExpired(ExpiredJwtTokenException ex) {
        return build(HttpStatus.UNAUTHORIZED, ex.getMessage(), "The JWT token has expired");
    }

    @ExceptionHandler(InvalidJwtException.class)
    public ProblemDetail handleMalformed(InvalidJwtException ex) {
        return build(HttpStatus.UNAUTHORIZED, ex.getMessage(), "The JWT token is malformed");
    }

    @ExceptionHandler(Exception.class)
    public ProblemDetail handleOthers(Exception ex) {
        ex.printStackTrace();
        return build(HttpStatus.INTERNAL_SERVER_ERROR, ex.getMessage(), "Unknown internal server error.");
    }

    private ProblemDetail build(HttpStatus status, String detail, String description) {
        ProblemDetail pd = ProblemDetail.forStatusAndDetail(status, detail);
        pd.setProperty("description", description);
        return pd;
    }
}
