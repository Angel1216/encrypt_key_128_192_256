package com.adswaresystem.encriptacion.aes256;

import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
 
/**
 * @version 1.0
 * Clase que contiene los métodos públicos encrypt y descrypt, cuyos objetivos son
 * encriptar y desencriptar respectivamente, utilizando el algoritmo AES en modo Modo ECB (Electronic codebook)
 * soportando claves de 128/192/256 bits
 * Requiere la librería Bouncy Castle
 * @see <a href="https://www.bouncycastle.org/latest_releases.html">Bouncy Castle</a>
 * @see <a href="http://es.wikipedia.org/wiki/Advanced_Encryption_Standard">WikiES: Advanced Encryption Standard</a>
 * @see <a href="http://es.wikipedia.org/wiki/Criptograf%C3%ADa">WikiES: Criptografía</a>
 * @see <a href="https://es.wikipedia.org/wiki/Modos_de_operaci%C3%B3n_de_una_unidad_de_cifrado_por_bloques#Modo_ECB_.28Electronic_codebook.29">WikiES: Modo ECB (Electronic codebook)</a>
 * @see <a href="http://www.linkedin.com/in/juliofcv">Julio Chinchilla</a>
 * @author Julio Chinchilla
 */
public class AESECB {
 
    /**
     * Función de tipo arreglo de bytes que recibe una llave (key)
     * y un arreglo de bytes (input) el cual se desea encriptar
     * @param key recibe únicamente claves de 128/192/256 bits
     * @param input arreglo de bytes a cifrar
     * @return el texto cifrado en modo String
     * @throws Exception puede devolver excepciones de los siguientes tipos: DataLengthException, InvalidCipherTextException
     */
    public static byte[] encrypt(byte[] key, byte[] input) throws Exception {
        return processing(key, input, true);
    }
 
    /**
     * Función de tipo arreglo de bytes que recibe una llave (key)
     * y un arreglo de bytes (input) el cual se desea desencriptar
     * @param key recibe únicamente claves de 128/192/256 bits
     * @param input arreglo de bytes a descifrar
     * @return el texto cifrado en modo String
     * @throws Exception puede devolver excepciones de los siguientes tipos: DataLengthException, InvalidCipherTextException
     */
    public static byte[] decrypt(byte[] key, byte[] input) throws Exception {
        byte res1[] = processing(key, input, false);
        int i = res1.length-1;
        while(res1[i] == 0x00) {
            i--;
        }
        byte res0[] = new byte[i+1];
        System.arraycopy(res1, 0, res0, 0, res0.length);
        return res0;
    }
 
    /**
     * Clase interna de procesamiento que utiliza el API de Bouncy Castle
     * @param key recibe únicamente claves de 128/192/256 bits
     * @param input arreglo de bytes a codificar
     * @param encrypt true para encriptar y false para desencriptar
     * @return
     * @throws Exception
     */
    private static byte[] processing(byte[] key, byte[] input, boolean encrypt) throws Exception {
        PaddedBufferedBlockCipher pbbc = new PaddedBufferedBlockCipher(new AESEngine(), new PKCS7Padding());
        pbbc.init(encrypt, new KeyParameter(key));
        byte[] output = new byte[pbbc.getOutputSize(input.length)];
        int bytesWrittenOut = pbbc.processBytes(input, 0, input.length, output, 0);
        pbbc.doFinal(output, bytesWrittenOut);
        return output;
    }
 
}