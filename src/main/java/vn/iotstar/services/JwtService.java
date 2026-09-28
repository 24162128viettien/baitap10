package vn.iotstar.services;

import java.text.ParseException;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import vn.iotstar.exception.ExpiredJwtTokenException;
import vn.iotstar.exception.InvalidJwtException;
import vn.iotstar.exception.InvalidJwtSignatureException;

@Service
public class JwtService {

    @Value("${security.jwt.secret-key}")
    private String secretKey;

    @Value("${security.jwt.expiration-time}")
    private long jwtExpiration;

    // ================== ĐỌC / XÁC THỰC TOKEN ==================

    public String extractUsername(String token) {
        return extractClaim(token, JWTClaimsSet::getSubject);
    }

    public <T> T extractClaim(String token, Function<JWTClaimsSet, T> claimsResolver) {
        final JWTClaimsSet claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return username.equals(userDetails.getUsername()) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, JWTClaimsSet::getExpirationTime);
    }

    /** Parse + verify chữ ký + kiểm tra hạn -> trả về claims (payload). */
    private JWTClaimsSet extractAllClaims(String token) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(token);

            // Chỉ chấp nhận HS256 (chống tấn công đổi thuật toán)
            if (!JWSAlgorithm.HS256.equals(signedJWT.getHeader().getAlgorithm())) {
                throw new InvalidJwtSignatureException("Unsupported JWT algorithm");
            }
            if (!signedJWT.verify(new MACVerifier(getSignInKey()))) {
                throw new InvalidJwtSignatureException("The JWT signature is invalid");
            }

            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
            Date exp = claims.getExpirationTime();
            if (exp == null || exp.before(new Date())) {
                throw new ExpiredJwtTokenException("The JWT token has expired");
            }
            return claims;
        } catch (ParseException e) {
            throw new InvalidJwtException("Invalid JWT string: " + e.getMessage(), e);
        } catch (JOSEException e) {
            throw new InvalidJwtSignatureException("Cannot verify JWT: " + e.getMessage());
        }
    }

    // ================== SINH TOKEN ==================

    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        return buildToken(extraClaims, userDetails, jwtExpiration);
    }

    public long getExpirationTime() {
        return jwtExpiration;
    }

    private String buildToken(Map<String, Object> extraClaims, UserDetails userDetails, long expiration) {
        try {
            Date now = new Date();

            // PAYLOAD: registered claims (sub, iat, exp) + private claims
            JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
                    .subject(userDetails.getUsername())
                    .issueTime(now)
                    .expirationTime(new Date(now.getTime() + expiration));
            extraClaims.forEach(claimsBuilder::claim);

            // HEADER: {"alg":"HS256","typ":"JWT"}
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS256)
                    .type(JOSEObjectType.JWT)
                    .build();

            SignedJWT signedJWT = new SignedJWT(header, claimsBuilder.build());

            // SIGNATURE: HMAC-SHA256(base64url(header) + "." + base64url(payload), secret)
            signedJWT.sign(new MACSigner(getSignInKey()));

            return signedJWT.serialize(); // header.payload.signature
        } catch (JOSEException e) {
            throw new IllegalStateException("Cannot sign JWT", e);
        }
    }

    private byte[] getSignInKey() {
        return Base64.getDecoder().decode(secretKey);
    }
}
