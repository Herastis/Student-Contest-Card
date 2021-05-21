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
import java.util.*;

public class Main {
    private static final String capFilePath =
            "C:\\Program Files (x86)\\Oracle\\Java Card Development Kit Simulator 3.1.0\\samples\\classic_applets\\Wallet\\applet\\apdu_scripts\\cap-Wallet.script";
    int[] contest_codes = new int[]{10, 20, 30, 40, 50};
    public static void main(String[] args) throws IOException, CadTransportException, GeneralSecurityException {
        runServer(); //run server without eclipse

        CadClientInterface cad;
        Socket sock;
        sock = new Socket("localhost", 9025);
        InputStream is = sock.getInputStream();
        OutputStream os = sock.getOutputStream();
        cad = CadDevice.getCadClientInstance(CadDevice.PROTOCOL_T1, is, os);
        cad.powerUp();


        // Parse the CAP file
        try(Stream<String> stream = Files.lines(Paths.get(capFilePath))) {
            stream.filter(s -> !s.isEmpty() && s.charAt(1) != '/' && !s.equals("powerup;"))
                    .map(s -> {
                        List<String[]> strings = new ArrayList<>();

                        String[] splits = s.split(" ");
                        strings.add(Arrays.copyOfRange(splits, 0, 4));
                        strings.add(Arrays.copyOfRange(splits, 5, splits.length - 1));
                        strings.add(Arrays.copyOfRange(splits, splits.length - 1, splits.length));

                        return strings;
                    })
                    .forEach(strings -> {
                        Apdu apdu = new Apdu();

                        List<Byte> collect = Arrays.stream(strings.get(0))
                                .map(s -> {
                                    byte b = 0;
                                    b += Integer.parseInt(String.valueOf(s.charAt(2)), 16) * 16;
                                    b += Integer.parseInt(String.valueOf(s.charAt(3)), 16);

                                    return b;
                                })
                                .collect(Collectors.toList());
                        byte[] bytes = new byte[4];
                        for (int i = 0; i < collect.size(); i++) {
                            Byte aByte = collect.get(i);
                            bytes[i] = aByte;
                        }
                        apdu.command = bytes;

                        collect = Arrays.stream(strings.get(1))
                                .map(s -> {
                                    byte b = 0;
                                    b += Integer.parseInt(String.valueOf(s.charAt(2)), 16) * 16;
                                    b += Integer.parseInt(String.valueOf(s.charAt(3)), 16);

                                    return b;
                                })
                                .collect(Collectors.toList());
                        bytes = new byte[strings.get(1).length];
                        for (int i = 0; i < collect.size(); i++) {
                            Byte aByte = collect.get(i);
                            bytes[i] = aByte;
                        }
                        byte b = 0;
                        b += Integer.parseInt(String.valueOf(strings.get(2)[0].charAt(2)), 16) * 16;
                        b += Integer.parseInt(String.valueOf(strings.get(2)[0].charAt(3)), 16);

                        apdu.setDataIn(bytes);

                        try {
                            cad.exchangeApdu(apdu);
                        } catch (IOException | CadTransportException e) {
                            e.printStackTrace();
                        }

                        System.out.println(apdu);
                    });
        } catch (IOException e) {
            e.printStackTrace();
        }

        System.out.println();




        // create wallet
        Apdu apdu = new Apdu();
        apdu.command = new byte[]{(byte) 0x80, (byte) 0xB8, 0x00, 0x00};
        apdu.setDataIn(new byte[]{0x0a, (byte) 0xa0, 0x00, 0x00, 0x00, 0x62, 0x03, 0x01, 0x0c, 0x06, 0x01, 0x08, 0x00, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05});
        cad.exchangeApdu(apdu);

        System.out.println("Create wallet applet: 0x80 0xB8 0x00 0x00 0x14 0x0a 0xa0 0x0 0x0 0x0 0x62 0x3 0x1 0xc 0x6 0x1 0x08 0x0 0x0 0x05 0x01 0x02 0x03 0x04 0x05 0x7F");
        System.out.println(apdu);
        System.out.println("SW1: " +  byteToHexByte(apdu.getSw1Sw2()[0])+ " SW2: " +  byteToHexByte(apdu.getSw1Sw2()[1]));
        System.out.println();

        // select wallet
        apdu = new Apdu();
        apdu.command = new byte[]{0x00, (byte) 0xA4, 0x04, 0x00};
        apdu.setDataIn(new byte[]{(byte) 0xa0, 0x0, 0x0, 0x0, 0x62, 0x3, 0x1, 0xc, 0x6, 0x1});
        cad.exchangeApdu(apdu);

        System.out.println("Select wallet: 0x00 0xA4 0x04 0x00 0x0a 0xa0 0x0 0x0 0x0 0x62 0x3 0x1 0xc 0x6 0x1 0x7F");
        System.out.println(apdu);
        System.out.println("SW1: " +  byteToHexByte(apdu.getSw1Sw2()[0])+ " SW2: " +  byteToHexByte(apdu.getSw1Sw2()[1]));
        System.out.println();

        //verificam daca utilizatorul e student sau profesor
//        Scanner sc=new Scanner(System.in);
//        System.out.print("Ești un student? (da/nu)");
//        String ans = sc.nextLine();


        // a. Din aplicatia Terminal studentul introduce PIN-ul care este trimis la Java Card Applet pentru validare
        // verify user pin
        verifyUserPIN(cad);
        cad.exchangeApdu(apdu);

        // verify invalid user pin
        verifyInvalidUserPIN(cad);
        cad.exchangeApdu(apdu);


        //b. Daca PIN-ul este validat, comisia alege din meniul aplicatiei Terminal, codul concursului corespunzator si introduce punctajul pe card.
        choose_code(cad);
        cad.exchangeApdu(apdu);

        cad.powerDown(true);
    }



    public static String byteToHexByte(byte value) {
        StringBuilder sb = new StringBuilder();

        sb.append(String.format("%02X", value));
        String helper = "0x" + sb;

        return helper;
    }

    private static void runServer() {
        try {
            String crefFilePath = "c:\\Program Files (x86)\\Oracle\\Java Card Development Kit Simulator 3.1.0\\bin\\cref.bat";
            Process process;
            process = Runtime.getRuntime().exec(crefFilePath);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    private static void choose_code(CadClientInterface cad) throws IOException, CadTransportException {
        Apdu apdu;
        apdu = new Apdu();
        apdu.command = new byte[]{(byte) 0x80, (byte) 0x51, 0x00, 0x00};
        apdu.setDataIn(new byte[]{0x01, 0x02, 0x03, 0x04, 0x05});
        cad.exchangeApdu(apdu);

        //Verify user pin
        System.out.println("Verify choose code: 0x80 0x20 0x00 0x00 0x05 0x01 0x02 0x03 0x04 0x05 0x7F");
        System.out.println(apdu);
        System.out.println("SW1: " +  byteToHexByte(apdu.getSw1Sw2()[0])+ " SW2: " +  byteToHexByte(apdu.getSw1Sw2()[1]));
        //System.out.println(apdu.getSw1Sw2());
        System.out.println();
    }


    private static void verifyUserPIN(CadClientInterface cad) throws IOException, CadTransportException {
        Apdu apdu;// verify PIN
        apdu = new Apdu();
        apdu.command = new byte[]{(byte) 0x80, (byte) 0x20, 0x00, 0x00};
        apdu.setDataIn(new byte[]{0x01, 0x02, 0x03, 0x04, 0x05});
        cad.exchangeApdu(apdu);

        //Verify user pin
        System.out.println("Verify user pin: 0x80 0x20 0x00 0x00 0x05 0x01 0x02 0x03 0x04 0x05 0x7F");
        System.out.println(apdu);
        System.out.println("SW1: " +  byteToHexByte(apdu.getSw1Sw2()[0])+ " SW2: " +  byteToHexByte(apdu.getSw1Sw2()[1]));
        //System.out.println(apdu.getSw1Sw2());
        System.out.println();
    }

    private static void verifyInvalidUserPIN(CadClientInterface cad) throws IOException, CadTransportException {
        Apdu apdu;// verify PIN
        apdu = new Apdu();
        apdu.command = new byte[]{(byte) 0x80, (byte) 0x20, 0x00, 0x00};
        apdu.setDataIn(new byte[]{0x01, 0x02, 0x03, 0x04, 0x06});
        cad.exchangeApdu(apdu);

        System.out.println("Verify invalid user pin: 0x80 0x20 0x00 0x00 0x04 0x01 0x03 0x02 0x66 0x7F");
        System.out.println(apdu);
        System.out.println("SW1: " +  byteToHexByte(apdu.getSw1Sw2()[0])+ " SW2: " +  byteToHexByte(apdu.getSw1Sw2()[1]));
        //System.out.println(apdu.getSw1Sw2());
        System.out.println();
    }


}
