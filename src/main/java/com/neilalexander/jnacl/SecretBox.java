package com.neilalexander.jnacl;

import com.neilalexander.jnacl.crypto.xsalsa20poly1305;

/**
 * Created by Julian on 8/1/14.
 */
public class SecretBox {
    static final int crypto_secretbox_KEYBYTES = 32;
    static final int crypto_secretbox_NONCEBYTES = 24;
    static final int crypto_secretbox_ZEROBYTES = 32;
    static final int crypto_secretbox_BOXZEROBYTES = 16;
    static final int crypto_secretbox_BEFORENMBYTES = 32;

    private byte[] key;

    public SecretBox(byte[] key) {
        this.key = key;
    }

    public byte[] encrypt(byte[] nonce, byte[] input) {
        byte[] paddedinput = new byte[input.length + crypto_secretbox_ZEROBYTES];
        byte[] paddedoutput = new byte[paddedinput.length];
        byte[] output = new byte[paddedoutput.length - crypto_secretbox_BOXZEROBYTES];

        System.arraycopy(input, 0, paddedinput, crypto_secretbox_ZEROBYTES, input.length);
        xsalsa20poly1305.crypto_secretbox(paddedoutput, paddedinput, paddedinput.length, nonce, this.key);
        System.arraycopy(paddedoutput, crypto_secretbox_BOXZEROBYTES, output, 0 , output.length);

        return output;
    }

    public byte[] decrypt(byte[] nonce, byte[] input) {
        byte[] paddedinput = new byte[input.length + crypto_secretbox_BOXZEROBYTES];
        byte[] paddedoutput = new byte[paddedinput.length];
        byte[] output = new byte[paddedoutput.length - crypto_secretbox_ZEROBYTES];

        System.arraycopy(input, 0, paddedinput, crypto_secretbox_BOXZEROBYTES, input.length);
        xsalsa20poly1305.crypto_secretbox_open(paddedoutput, paddedinput, paddedinput.length, nonce, this.key);
        System.arraycopy(paddedoutput, crypto_secretbox_ZEROBYTES, output, 0, paddedoutput.length - crypto_secretbox_ZEROBYTES);

        return output;
    }

}
