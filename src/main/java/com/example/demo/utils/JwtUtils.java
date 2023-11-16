package com.example.demo.utils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class JwtUtils {
    private static final Logger LOGGER = LogManager.getLogger(JwtUtils.class);

    public String generateToken(String userName) {
        Map<String, Object> claims = new HashMap<>(2);
        claims.put(Claims.SUBJECT, userName);
        claims.put(Claims.ISSUED_AT, new Date());

        Date expirationDate = new Date(System.currentTimeMillis() + (int) Math.ceil(1.0 * 1800 / 2) * 1000L);

        return Jwts.builder().setClaims(claims).setExpiration(expirationDate).signWith(getSignKey(), SignatureAlgorithm.RS256).compact();
    }

    public String getUserNameFromToken(String token) {
        Claims claims = getClaimsFromToken(token);
        return null != claims ? claims.getSubject() : null;
    }

    public Boolean isTokenExpired(String token) {
        Claims claims = getClaimsFromToken(token);
        return null == claims || claims.getExpiration().before(new Date());
    }

    private Claims getClaimsFromToken(String token) {
        return Jwts.parser().setSigningKey(getSignKey()).parseClaimsJws(token).getBody();
    }

    private PrivateKey getSignKey() {
        //https://www.devglan.com/online-tools/rsa-encryption-decryption
        String secret = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCT4spjRD7s5K5zXmuGmmxo5nhsvugwnKFN+ijmqcLUdfCUYfXINIDvETr3X1CcAvot8YuggcRoVFTSZzZk9RkiD7VRxggjpCtxbH7M0sDqvXEqK59Y3T4ht5tX3YiBJNPDRZgwTHEzXzoy8fhCxSiagP5MwxseZV9jNJKrn/z/59QFtHwOhXDl8otcPVetaRf9c9RJ/eZwHDVxVzULlB3x6ho1mXBUa8B/L+8LkrFKKELXxfa6XYsVyduEbJYH2lfC/T9lPhqqQ7r755yMuteNJ8JFWuI0kDSQXRjsOBFgQ7gtroJSlUeWvSEXDW+Ut7giq+iFT5yqZdnoaMWqyG4NAgMBAAECggEAFL3ydQnVaZSJg1Ty7+Yo3m205kvAdVECrtUvd2rIENSZ8bXrqzDyBJX+F0QfIkKopFkEpHaO/bMWUox3bKGT7NsXK2kDKzyTe00kW8YTmNkJTkjgCK6/UCtYdnJz+ukXaoQQXHXcSsBIgWy+zV6p20HMaSfUXecKAfgVukyuR5Yd5JxzDYalKwtw8g8bwR/GZC8f/iTc7Axzn4BQSVBKf9lPGaghgoZXv6whmGyP3QKXSFgRPYE/XXEZCMTCkiWFKJXNyCAk0vPAgzMy2DW2/Cylzc+sNCZL1V0iU0Ot0UHrxdToREqhtEICLvXm9yEEBsTlylhA9H1y0FB0GMBlAQKBgQDIDr8l2mEB3iDX2RZWqQ1/cIdGYQJTM5z+imuxEcFcz3o73j+gXr+ZX7uHOR3yveEeySRt7CYMlkEr1uPj3teohY81A7+0ddr+gt/1Kfh7Ceqjs2L/PPPF338BMxGHC1vUQ/aGDxaazth4EiyeBLW0dlrd6eoN9D+CIS5Xk9/3ZQKBgQC9PUx2O3KP9U9AK5bpZLujIn5fpKuA8O27zhRLVrc+WHjPVLLYWikU6ImJVqES8kDIZ1MQVkefgmrfh0X8KTsSqaEbmCNbpZOj/mKcmKluD7nVbCmD8mq/d1uKAoIVAAZ/NpEMRaRiZU+mGHuAUoPR/oFDOE3ZN92BgS1ieF7ViQKBgQCntAT0nF3ZjPWHO8oIF2rjO9eKXePvD0M59ZtVMgcf4CUdbq9zpjmDPscbEfxS8m12uzK4ms9CmepD773V1YZ/FIb58AySIIHV/Kv0/pv3uFZjqAsC33uSkkoLHV5CEHmINPjBZICUgXThIosYY+ZWQyjlAiNcUzWxxlLsw19qKQKBgFTYzxeTv+Hb0xSqdpdemuKh7JdldZ/yZiT2WRMOZkqF0GTlTOrEQfcl68SwGrgr9e/ko9GHXcWe69wdArv0oI/Vjm6Y4AGPU4sL25rqt8ypMGEIhfSrFEGUem5+gWR5BnCzPoWKFBIp6nRGNdlrJb9ZpQtGi2EBM0eFa5vi7GJBAoGBAL6cZG3k6bsjGv00PCW8o8z3yxKN5ywQvDGK7beqiv3SVGwvPrORM7w34bNlwmvJd68xAbSrYO2PfWf4eHUtooVNjlKPPYJxJSwWPHZeyTlxr1QyuNZzCNhEclBi7y/Bn0fB7+T1KyUp6/+3T2ms36PK39RxGTa6o6BPxkzxVD9l";
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(secret));
        PrivateKey privateKey = null;
        try {
            KeyFactory kf = KeyFactory.getInstance("RSA");
            privateKey = kf.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            LOGGER.error("Failed to generate private key.", e);
        }
        return privateKey;
    }
}