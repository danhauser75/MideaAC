package org.openhab.binding.mideaac.internal.security;

import java.util.ArrayList;

public class Decryption8370Result {
    public ArrayList<byte[]> getResponses() {
        return responses;
    }

    public byte[] getBuffer() {
        return buffer;
    }

    ArrayList<byte[]> responses;
    byte[] buffer;

    public Decryption8370Result(ArrayList<byte[]> responses, byte[] buffer) {
        super();
        this.responses = responses;
        this.buffer = buffer;
    }
}
