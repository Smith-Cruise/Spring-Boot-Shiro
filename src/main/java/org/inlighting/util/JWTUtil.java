package org.inlighting.util;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;

import java.io.UnsupportedEncodingException;

public class JWTUtil {

    /**
     * 校验token是否正确
     * @param token 密钥
     * @param username 用户名
     * @param secret 用户的密码
     * @return 是否正确
     */
    public static boolean verify(String token, String username, String secret) {
        try {
            Algorithm algorithm = Algorithm.HMAC256(secret);
            JWTVerifier verifier = JWT.require(algorithm)
                    .withClaim("username", username)
                    .build();
            DecodedJWT jwt = verifier.verify(token);
            return true;
        } catch (Exception exception) {
            return false;
        }
    }

    /**
     * 生成签名
     * @param username 用户名
     * @param secret 用户的密码
     * @return 加密的token
     */
    public static String sign(String username, String secret) {
        try {
            Algorithm algorithm = Algorithm.HMAC256(secret);
            // 附带username信息
            String token = JWT.create()
                    .withClaim("username", username)
                    .sign(algorithm);
            return token;
        } catch (UnsupportedEncodingException e) {
            return null;
        }
    }
}
