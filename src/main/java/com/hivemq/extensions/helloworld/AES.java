package com.hivemq.extensions.helloworld;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class AES {
    private IvParameterSpec iv;
    private SecretKeySpec secretKey;
    public AES (byte[] aes_key,byte[] aes_iv)
    {
        this.iv=new IvParameterSpec(aes_iv);
        this.secretKey= new SecretKeySpec(aes_key, "AES");
    }

    public String AES_CBC_Decryption (String ciphermsg) throws Exception
    {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);
        byte[] Decodedmsg=Base64.getDecoder().decode(ciphermsg);
        byte[] DecryptedMessage = cipher.doFinal(Decodedmsg);

        String originalMessage = new String(DecryptedMessage, StandardCharsets.UTF_8);
        return originalMessage;
    }
}