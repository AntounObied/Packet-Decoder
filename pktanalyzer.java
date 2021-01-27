/**
 * @author: Antoun Obied
 * CSCI651
 * Project1
 *
 * This program reads and decodes data packets, depending on the types of protocols used in the packets
 * Protocols that can be processed using this program: Ethernet, IP, ARP, ICMP, UDP, TCP
 */

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;

public class pktanalyzer {

    private String fileName;
    private static File file;
    private static byte[] data; // Stores all bytes in packet to array
    private static String[] hexData; // Stores the hexadecimal form of bytes in the packet
    private static int IPHeaderLength;
    private static int index = 14; // Index for IP and ARP headers to start reading from the array
    private static int protocolIndex; // Index for each specific protocol to read from array after Ether and IP headers

    /**
     * Method reads bytes from a packet, then places them in byte array
     * Also converts the byte array into hexadecimal format
     * @param fileName
     * @throws IOException
     */
    private void setData(String fileName) throws IOException {
        this.fileName = fileName;
        file = new File(fileName);
        FileInputStream inputStream = new FileInputStream(file);
        data = new byte[(int) file.length()];
        inputStream.read(data);
        hexData = new String[data.length];
        for (int i = 0; i < data.length; i++){
            hexData[i] = String.format("%02x", data[i]);
        }
    }

    /**
     * Method converts from hexidecimal value to binary, with leading zeros
     * Source : https://stackoverflow.com/questions/32186197/converting-hex-to-binary-with-leading-zeros
     * @param hex
     * @return
     */
    private static String hexToBin(String hex){
        String value = new BigInteger(hex, 16).toString(2);
        return String.format("%8s", value).replace(" ", "0");
    }

    /**
     * Method convers from hexadecimal to ASCII
     * Source: https://howtodoinjava.com/java/convert-hex-to-ascii-and-ascii-to-hex/
     * @param hex
     * @return
     */
    private static char hexToASCII(String hex){
        int value = Integer.parseInt(hex, 16);
        return (char)value;
    }

    /**
     * Method first decodes the ethernet header
     * If ethertype is 0800, this method will invoke printIPHeader()
     * If ethertype is 0806, this method will invoke printARPHeader()
     */
    private void decodePacket(){
        String result = "";
        String etherType = hexData[12] + hexData[13];


        result += "ETHER: ---- Ether Header ----\nETHER:\n";
        result += "ETHER: Packet size = " + data.length + " bytes\n";
        result += "ETHER: Destination = ";
        for (int i = 0; i < 5; i++){
            result += hexData[i] + ":";
        }
        result += hexData[5] + "\nETHER: Source = ";
        for (int i = 6; i < 11; i++){
            result += hexData[i] + ":";
        }
        result += hexData[11] + "\nETHER: Ethertype = " + etherType + "\nETHER:";
        System.out.println(result);

        switch (etherType){
            case "0800":
                printIPHeader();
                break;
            case "0806":
                printARPHeader();
                break;
        }
    }

    /**
     * Method decodes IP header in data packet
     * Based on protocol type seen in IP header, this method will invoke the next one
     * For protocol number 1, invoke printICMP()
     * For protocol number 6, invoke printTCP()
     * For protocol number 17, invoke printUDP()
     */
    private void printIPHeader(){
        int version = Integer.parseInt(hexData[index].substring(0, 1));
        IPHeaderLength = Integer.parseInt(hexData[index].substring(1, 2)) * 4;
        String DSCP = hexToBin(hexData[++index]).substring(0, 6);
        String ECN = hexToBin(hexData[index]).substring(6);
        int totalLength = Integer.parseInt((hexData[++index] + hexData[++index]), 16);
        int identification = Integer.parseInt((hexData[++index] + hexData[++index]), 16);
        String flag = "0x" + hexData[++index].charAt(0);
        int flagBit1 = (Integer.parseInt(String.valueOf(hexToBin(hexData[index]).charAt(1)))) & 1;
        String flagBit1Msg = "";
        int flagBit2 = (Integer.parseInt(String.valueOf(hexToBin(hexData[index]).charAt(2)))) & 1;
        String flagBit2Msg = "";

        switch (flagBit1){
            case 0: flagBit1Msg = "OK to fragment"; break;
            case 1: flagBit1Msg = "Do not fragment"; break;
        }

        switch (flagBit2){
            case 0: flagBit2Msg = "Last fragment"; break;
            case 1: flagBit2Msg = "Not last fragment"; break;
        }

        int fragOffset = Integer.parseInt(hexToBin(hexData[index]).substring(3) + hexToBin(hexData[++index]));
        int timeToLive = Integer.parseInt(hexData[++index], 16);
        int protocol = Integer.parseInt(hexData[++index], 16);
        String protocolName;

        switch (protocol){
            case 1: protocolName = "(ICMP)"; break;
            case 6: protocolName = "(TCP)"; break;
            case 17: protocolName = "(UDP)"; break;
            default: protocolName = "(Unknown protocol)"; break;
        }

        String headerChecksum = "0x" + hexData[++index] + hexData[++index];
        String srcAddress = "" + Integer.parseInt(hexData[++index], 16) + "." + Integer.parseInt(hexData[++index], 16)
                + "." + Integer.parseInt(hexData[++index], 16) + "." + Integer.parseInt(hexData[++index], 16);
        String destAddress = "" + Integer.parseInt(hexData[++index], 16) + "." + Integer.parseInt(hexData[++index], 16)
                + "." + Integer.parseInt(hexData[++index], 16) + "." + Integer.parseInt(hexData[++index], 16);

        String options = "No options";
        if (IPHeaderLength > 20){
            options = "Options available";
        }

        String result = "";
        result += "IP: ---- IP Header ----\nIP: \nIP: Version = " + version + "\nIP: ";
        result += "Header Length = " + IPHeaderLength + " bytes\nIP: DSCP = " + DSCP + "\nIP: ECN = " + ECN + "\nIP: ";
        result += "Total Length = " + totalLength + " bytes\nIP: Identification = " + identification + "\nIP: Flags = " + flag + "\nIP:";
        result += "      ." + flagBit1 + ".. .... = " + flagBit1Msg + "\nIP:      .." + flagBit2 + ". .... = " + flagBit2Msg + "\nIP: ";
        result += "Fragment offset = " + fragOffset + " bytes\nIP: ";
        result += "Time to Live = " + timeToLive + " seconds per hops\nIP: Protocol = " + protocol + " " + protocolName;
        result += "\nIP: Header Checksum = " + headerChecksum + "\nIP: Source Address = " + srcAddress + "\nIP: ";
        result += "Destination Address = " + destAddress + "\nIP: " + options + "\nIP:";
        System.out.println(result);

        switch (protocol){
            case 1: printICMP(); break;
            case 6: printTCP(); break;
            case 17: printUDP(); break;
            default:
                System.out.println("Unknown protocol"); break;
        }
    }

    /**
     * Method decodes and prints data in ARP header of a packet, if applicable
     */
    private void printARPHeader(){
        String result = "";
        int hardwareType = Integer.parseInt((hexData[index] + hexData[++index]), 16);
        String hardwareName = "";
        if (hardwareType == 1){
            hardwareName = "Ethernet";
        }
        String protocolType = hexData[++index] + hexData[++index];
        int hwAddrLength = Integer.parseInt(hexData[++index], 16);
        int protocolAddrLength = Integer.parseInt(hexData[++index], 16);
        int opcode = Integer.parseInt((hexData[++index] + hexData[++index]), 16);
        String opcodeType = "";
        switch (opcode){
            case 1: opcodeType = "Request"; break;
            case 2: opcodeType = "Reply"; break;
        }
        String senderMAC = hexData[++index] + ":" + hexData[++index] + ":" + hexData[++index] + ":" + hexData[++index] + ":"
                + hexData[++index] + ":" + hexData[++index];
        String senderIP = "" + Integer.parseInt(hexData[++index], 16) + "." + Integer.parseInt(hexData[++index], 16) + "."
                + Integer.parseInt(hexData[++index], 16) + "." + Integer.parseInt(hexData[++index], 16);
        String targetMAC = hexData[++index] + ":" + hexData[++index] + ":" + hexData[++index] + ":" + hexData[++index] + ":"
                + hexData[++index] + ":" + hexData[++index];
        String targetIP = "" + Integer.parseInt(hexData[++index], 16) + "." + Integer.parseInt(hexData[++index], 16) + "."
                + Integer.parseInt(hexData[++index], 16) + "." + Integer.parseInt(hexData[++index], 16);

        result += "ARP: ---- ARP Header ----\nARP:\nARP: Hardware Type = " + hardwareType + " (" + hardwareName + ")";
        result += "\nARP: Protocol Type = " + protocolType + "\nARP: Hardware Address Length = " + hwAddrLength;
        result += "\nARP: Protocol Address Length = " + protocolAddrLength + "\nARP: Opcode = " + opcode + " (" + opcodeType + ")";
        result += "\nARP: Sender MAC Address = " + senderMAC + "\nARP: Sender IP Address = " + senderIP;
        result += "\nARP: Target MAC Address = " + targetMAC + "\nARP: Target IP Address = " + targetIP;
        System.out.println(result);
    }

    /**
     * Method decodes and prints data in ICMP header of a packet, if applicable
     */
    private void printICMP(){
        protocolIndex = 14 + IPHeaderLength;
        String result = "";
        int type = Integer.parseInt(hexData[protocolIndex], 16);
        String typeName = "";

        switch (type){
            case (0): typeName = "(Echo Reply)"; break;
            case (3): typeName = "(Destination Unreachable)"; break;
            case (8): typeName = "(Echo Request)"; break;
            case (11): typeName = "(Time Exceeded)"; break;
        }

        int code = Integer.parseInt(hexData[++protocolIndex], 16);
        String checksum = "0x" + hexData[++protocolIndex] + hexData[++protocolIndex];

        result += "ICMP: ---- ICMP Header ----\nICMP:\nICMP: Type = " + type + " " + typeName + "\nICMP: Code = " + code;
        result += "\nICMP: Checksum = " + checksum + "\nICMP:";
        System.out.println(result);
    }

    /**
     * Method decodes and prints data in TCP header of a packet, if applicable
     */
    private void printTCP(){
        protocolIndex = 14 + IPHeaderLength;
        String result = "";
        int srcPort = Integer.parseInt((hexData[protocolIndex] + hexData[++protocolIndex]), 16);
        int destPort = Integer.parseInt((hexData[++protocolIndex] + hexData[++protocolIndex]), 16);
        long seqNumber = Long.parseLong((hexData[++protocolIndex] + hexData[++protocolIndex] + hexData[++protocolIndex] + hexData[++protocolIndex]), 16);
        long ackNumber = Long.parseLong((hexData[++protocolIndex] + hexData[++protocolIndex] + hexData[++protocolIndex] + hexData[++protocolIndex]), 16);
        int dataOffset = Integer.parseInt((hexData[++protocolIndex].substring(0, 1)), 16);
        int TCPheaderLength = dataOffset * 4;
        String flags = "0x" + hexData[++protocolIndex];
        int urg = (Integer.parseInt(String.valueOf(hexToBin(hexData[protocolIndex]).charAt(2)))) & 1;
        String urgMsg = "";
        int ack = (Integer.parseInt(String.valueOf(hexToBin(hexData[protocolIndex]).charAt(3)))) & 1;
        String ackMsg = "";
        int push = (Integer.parseInt(String.valueOf(hexToBin(hexData[protocolIndex]).charAt(4)))) & 1;
        String pushMsg = "";
        int reset = (Integer.parseInt(String.valueOf(hexToBin(hexData[protocolIndex]).charAt(5)))) & 1;
        String resetMsg = "";
        int syn = (Integer.parseInt(String.valueOf(hexToBin(hexData[protocolIndex]).charAt(6)))) & 1;
        String synMsg = "";
        int fin = (Integer.parseInt(String.valueOf(hexToBin(hexData[protocolIndex]).charAt(7)))) & 1;
        String finMsg = "";
        int window = Integer.parseInt((hexData[++protocolIndex] + hexData[++protocolIndex]), 16);
        String checksum = "0x" + hexData[++protocolIndex] + hexData[++protocolIndex];
        int urgentPointer = Integer.parseInt((hexData[++protocolIndex] + hexData[++protocolIndex]), 16);
        String options = "No options";

        switch (urg){
            case (0): urgMsg = "No urgent pointer"; break;
            case (1): urgMsg = "Urgent pointer"; break;
        }

        switch (ack){
            case (0): ackMsg = "No Acknowledgement"; break;
            case (1): ackMsg = "Acknowledgment"; break;
        }

        switch (push){
            case (0): pushMsg = "No Push"; break;
            case (1): pushMsg = "Push"; break;
        }

        switch (reset){
            case (0): resetMsg = "No Reset"; break;
            case (1): resetMsg = "Reset"; break;
        }

        switch (syn){
            case (0): synMsg = "No Syn"; break;
            case (1): urgMsg = "Syn"; break;
        }

        switch (fin){
            case (0): finMsg = "No Fin"; break;
            case (1): finMsg = "Fin"; break;
        }

        if (TCPheaderLength > 20){
            options = "Options available";
        }

        result += "TCP: ---- TCP Header ----\nTCP:\nTCP: Source port = " + srcPort;
        result += "\nTCP: Destination port = " + destPort + "\nTCP: Sequence number = " + seqNumber + "\nTCP: ";
        result += "Acknowledgement = " + ackNumber + "\nTCP: Data offset = " + dataOffset + " bytes\nTCP: Flags = ";
        result += flags + "\nTCP:      .." + urg + ". .... = " + urgMsg + "\nTCP:      ";
        result += "..." + ack + " .... = " + ackMsg + "\nTCP:      ...." + push + "... = " + pushMsg + "\nTCP:      ";
        result += ".... ." + reset + ".. = " + resetMsg + "\nTCP:      .... .." + syn + ". = " + synMsg + "\nTCP:      ";
        result += ".... ..." + fin + " = " + finMsg;
        result += "\nTCP: Window = " + window + "\nTCP: Checksum = " + checksum;
        result += "\nTCP: Urgent Pointer = " + urgentPointer + "\nTCP: " + options + "\nTCP:\n";
        result += "TCP: Data: (first 64 bytes)";

        int startRead = 14 + IPHeaderLength;
        int endRead = 14 + 64 + IPHeaderLength;

        if (file.length() < endRead){
            endRead = (int) file.length();
        }

        for (int i = startRead, j = 0; i < endRead && j < 64; i++, j++){
            if (j % 2 == 0){
                result += " ";
            }
            if (j % 16 == 0){
                result += "\nTCP: ";
            }
            result += hexData[i];
        }

        for (int i = startRead, j = 0; i < endRead && j < 64; i++, j++){
            if (j % 16 == 0){
                result += "\nTCP: ";
            }
            result += "" + hexToASCII(hexData[i]) + "";
        }

        System.out.println(result);
    }

    /**
     * Method decodes and prints data in UDP header of a packet, if applicable
     */
    private void printUDP(){
        protocolIndex = 14 + IPHeaderLength;
        String result = "";
        int srcPort = Integer.parseInt((hexData[protocolIndex] + hexData[++protocolIndex]), 16);
        int destPort = Integer.parseInt((hexData[++protocolIndex] + hexData[++protocolIndex]), 16);
        int length = Integer.parseInt((hexData[++protocolIndex] + hexData[++protocolIndex]), 16);
        String checksum = "0x" + hexData[++protocolIndex] + hexData[++protocolIndex];

        result += "UDP: ---- UDP Header ----\nUDP:\nUDP: Source port = " + srcPort + "\nUDP: Destination port = " + destPort;
        result += "\nUDP: Length = " + length + "\nUDP: Checksum = " + checksum + "\nUDP:\nUDP: Data : (first 64 bytes)";

        int startRead = 14 + IPHeaderLength;
        int endRead = 14 + 64 + IPHeaderLength;

        if (file.length() < endRead){
            endRead = (int) file.length();
        }

        for (int i = startRead, j = 0; i < endRead && j < 64; i++, j++){
            if (j % 2 == 0){
                result += " ";
            }
            if (j % 16 == 0){
                result += "\nUDP: ";
            }
            result += hexData[i];
        }

        for (int i = startRead, j = 0; i < endRead && j < 64; i++, j++){
            if (j % 16 == 0){
                result += "\nUDP: ";
            }
            result += "" + hexToASCII(hexData[i]) + "";
        }
        System.out.println(result);
    }

    public static void main(String[] args) throws IOException {
        pktanalyzer test = new pktanalyzer();
        test.setData(args[0]);
        test.decodePacket();
    }
}