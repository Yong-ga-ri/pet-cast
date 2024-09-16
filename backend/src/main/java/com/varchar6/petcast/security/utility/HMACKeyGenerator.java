package com.varchar6.petcast.security.utility;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.util.Base64;

public class HMACKeyGenerator {
    public static void main(String[] args) {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA512");
            keyGen.init(512);

            SecretKey secretKey = keyGen.generateKey();

            String encodedKey = Base64.getEncoder().encodeToString(secretKey.getEncoded());

            System.out.println("HS512 Key: " + encodedKey);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
