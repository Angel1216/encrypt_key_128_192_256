package com.adswaresystem.encriptacion.test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import com.adswaresystem.encriptacion.aes256.AESECB;

public class Testing {
 
    private static final byte[] KEY_128 = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    };
 
    private static final byte[] KEY_192 = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    };
 
    private static final byte[] KEY_256 = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    };
    
    private static final byte[] KEY_256_2 = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x00, 0x01, 0x02, 0x01, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    };
 
    public static void main(String[] args) throws Exception {
           testAESECB128();
           testAESECB192();
           testAESECB256();
           testAESECB256Own1();
           testAESECB256Own2();
    }
    
    private static void testAESECB256Own1() throws Exception {
        
    	System.out.println("--------------AES ECB Key 256 OWN 1------------------");
        
    	// Texto Original
    	String encriptar = "texto a encriptar";
        System.out.println(encriptar);
        
        ////////////////////////////////////// Proceso para encriptar ////////////////////////////////
        
        // 1.- El texto a encriptar se transforma a array de bytes
        // 2.- Se encripta con un algoritmo AES a 256 Bits (Se sigue conservando el formato Array de Bytes)
        // 3.- Se transforma de Array de Bytes a Base64 para su envio como cadena de texto
        byte[] normal = encriptar.getBytes();
        byte[] enc = AESECB.encrypt(KEY_256,normal);
        String encoded = Base64.getEncoder().encodeToString(enc);
        System.out.println(encoded);
        
        // 4.- Se recibe texto codificado en Base64 y se transforma a Array de Bytes
        // 5.- Se desencripta (Se sigue conservando el formato Array de Bytes)
        // 6.- Se transforma de Array de Bytes a una cadena de texto
        // 7.- Se muestra el texto original encriptado
        byte[] B64ToByte = Base64.getDecoder().decode(encoded);
        byte[] dec = AESECB.decrypt(KEY_256,B64ToByte);
        String textoOriginal = new String(dec, StandardCharsets.UTF_8);
        System.out.println(textoOriginal);
    }
    
private static void testAESECB256Own2() throws Exception {
        
    	System.out.println("--------------AES ECB Key 256 OWN 2------------------");
        
    	// Texto Original
    	String encriptar = "texto a encriptar";
        System.out.println(encriptar);
        
        ////////////////////////////////////// Proceso para encriptar ////////////////////////////////
        
        // 1.- El texto a encriptar se transforma a array de bytes
        // 2.- Se encripta con un algoritmo AES a 256 Bits (Se sigue conservando el formato Array de Bytes)
        // 3.- Se transforma de Array de Bytes a Base64 para su envio como cadena de texto
        byte[] normal = encriptar.getBytes();
        byte[] enc = AESECB.encrypt(KEY_256_2,normal);
        String encoded = Base64.getEncoder().encodeToString(enc);
        System.out.println(encoded);
        
        // 4.- Se recibe texto codificado en Base64 y se transforma a Array de Bytes
        // 5.- Se desencripta (Se sigue conservando el formato Array de Bytes)
        // 6.- Se transforma de Array de Bytes a una cadena de texto
        // 7.- Se muestra el texto original encriptado
        byte[] B64ToByte = Base64.getDecoder().decode(encoded);
        byte[] dec = AESECB.decrypt(KEY_256_2,B64ToByte);
        String textoOriginal = new String(dec, StandardCharsets.UTF_8);
        System.out.println(textoOriginal);
    }
 
    private static void testAESECB256() throws Exception {
        System.out.println("--------------AES ECB Key 256 ------------------");
        byte[] normal = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F};
        System.out.println(byteToHex(normal));
        byte[] enc = AESECB.encrypt(KEY_256,normal);
        System.out.println(byteToHex(enc));
        byte[] dec = AESECB.decrypt(KEY_256,enc);
        System.out.println(byteToHex(dec));
    }
 
    private static void testAESECB192() throws Exception {
        System.out.println("--------------AES ECB Key 192 ------------------");
        byte[] normal = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F};
        System.out.println(byteToHex(normal));
        byte[] enc = AESECB.encrypt(KEY_192,normal);
        System.out.println(byteToHex(enc));
        byte[] dec = AESECB.decrypt(KEY_192,enc);
        System.out.println(byteToHex(dec));
    }
 
    private static void testAESECB128() throws Exception {
        System.out.println("--------------AES ECB Key 128 ------------------");
        byte[] normal = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F};
        System.out.println(byteToHex(normal));
        byte[] enc = AESECB.encrypt(KEY_128,normal);
        System.out.println(byteToHex(enc));
        byte[] dec = AESECB.decrypt(KEY_128,enc);
        System.out.println(byteToHex(dec));
    }
 
    public static String byteToHex(byte[] data)  {
        StringBuilder localStringBuilder = new StringBuilder();
        for (int i = 0; i < data.length; i++)  {
            String str;
            if ((str=Integer.toHexString(data[i]&0xFF).toUpperCase()).length()==1) {
                localStringBuilder.append(0);
            }
        localStringBuilder.append(str).append(" ");
        }
        return localStringBuilder.substring(0, localStringBuilder.length() - 1);
    }
 
}
