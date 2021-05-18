package com.company;
import com.sun.javacard.apduio.*;
import com.sun.javacard.apduio.Apdu;
import com.sun.javacard.apduio.CadClientInterface;
import com.sun.javacard.apduio.CadDevice;
import com.sun.javacard.apduio.CadTransportException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class Main {
    public static void main(String[] args) throws IOException, CadTransportException, GeneralSecurityException {
        CadClientInterface cad;
        Socket sock;
        sock = new Socket("localhost", 9025);
        InputStream is = sock.getInputStream();
        OutputStream os = sock.getOutputStream();
        cad = CadDevice.getCadClientInstance(CadDevice.PROTOCOL_T1, is, os);
        cad.powerUp();
        cad.powerDown(true);
    }
}
