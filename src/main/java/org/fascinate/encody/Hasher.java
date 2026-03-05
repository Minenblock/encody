package org.fascinate.encody;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class Hasher {

    // --- Helper Functions ---

    static int rotl(int val, int bits) {
        bits &= 7; // u8 rotate
        val &= 0xFF;
        return ((val << bits) | (val >>> (8 - bits))) & 0xFF;
    }

    static int sboxLookup(int[] sbox, int val) {
        return sbox[val & 0xFF];
    }

    // --- S-Box Initialization ---

    static int[] initSbox(byte[] bytes) {

        int len = bytes.length;
        int[] sbox = new int[256];

        for (int i = 0; i < 256; i++) {
            sbox[i] = i;
        }

        int seed = ((bytes[0] & 0xFF) + (bytes[len - 1] & 0xFF)) & 0xFF;

        // First mixing pass
        for (int i = 255; i >= 1; i--) {

            seed = (seed + (bytes[i % len] & 0xFF)) & 0xFF;
            seed ^= sbox[i];
            seed ^= sbox[(i + 7) % 256];
            seed ^= rotl(seed, i % 5);
            seed &= 0xFF;

            int j = ((seed ^ i) % 256 + 256) % 256;

            sbox[i] ^= bytes[i % len] & 0xFF;
            sbox[j] ^= bytes[(i + 1) % len] & 0xFF;

            int tmp = sbox[i];
            sbox[i] = sbox[j];
            sbox[j] = tmp;
        }

        // Second mixing pass
        for (int i = 255; i >= 1; i--) {

            seed ^= sbox[(i * 3) % 256];
            seed &= 0xFF;

            int j = ((seed ^ i) % 256 + 256) % 256;

            sbox[i] ^= bytes[(i + 16) % len] & 0xFF;

            int idx = (i + ((i * 11) ^ i)) % len;
            if (idx < 0) idx += len;

            sbox[j] ^= bytes[idx] & 0xFF;

            int tmp = sbox[i];
            sbox[i] = sbox[j];
            sbox[j] = tmp;
        }

        return sbox;
    }

    // --- Core Hash Round ---

    static void round(int[] state, int[] block, int[] sbox, byte[] bytes) {

        int len = Math.min(bytes.length, 64);

        for (int i = 0; i < state.length; i++) {

            int j = state.length - 1 - i;

            state[i] ^= rotl(state[j], 7);
            state[i] &= 0xFF;

            state[i] = (state[i] * 0x9E) & 0xFF;
            state[i] = (state[i] + state[(i + 1) % 8]) & 0xFF;

            state[i] ^= rotl(block[(i + 4) % len], 3);
            state[i] &= 0xFF;

            int idx = ((i % len) ^ (len * (state[i % len] & 0xFF))) % 64;
            if (idx < 0) idx += 64;

            int rot = ((block[idx] + sbox[idx]) & 0xFF) % 8;
            state[i] = rotl(state[i], rot);

            state[i] ^= rotl(state[(i + 7) % state.length], 3);
            state[i] &= 0xFF;

            state[i] = sboxLookup(sbox, state[i]);
        }

        // cross-byte mixing
        for (int i = 0; i < state.length; i++) {
            state[i] ^= state[(i + 3) % state.length];
            state[i] &= 0xFF;
        }

        // salt
        int salt =
                ((bytes[0] & 0xFF) +
                        ((bytes[bytes.length - 1] & 0xFF) *
                                sbox[(bytes.length - 1) % 256] & 0xFF)) & 0xFF;

        salt = rotl(salt, 3);

        for (int i = 0; i < state.length; i++) {

            int idx = (i + bytes.length - 1) % bytes.length;

            int mul = ((salt & 0xFF) * (bytes[idx] & 0xFF)) & 0xFF;
            salt ^= mul;
            salt &= 0xFF;

            state[i] ^= rotl(salt, i % 8);
            state[i] &= 0xFF;
        }

        // final mixing
        for (int i = 0; i < state.length; i++) {

            state[i] ^= state[(i + 3) % state.length];
            state[i] &= 0xFF;

            state[i] = (state[i] + state[(i + 5) % state.length]) & 0xFF;
            state[i] = (state[i] * state[(i + 3) % state.length]) & 0xFF;

            state[i] = rotl(state[i], 5);

            int idx = ((i % len) ^ (len * (state[(i + 3) % len] & 0xFF))) % 64;
            if (idx < 0) idx += 64;

            state[i] = rotl(state[i], (block[idx] % 8) + 1);

            state[i] ^= rotl(state[(i + 4) % state.length], 4);
            state[i] &= 0xFF;
        }
    }

    // --- End Mix ---

    static void endMix(int[] state, int[] block, int[] sbox) {

        for (int i = 0; i < state.length; i++) {

            state[i] ^= block[i];
            state[i] &= 0xFF;

            state[i] = rotl(state[i], sbox[state[i]]);

            state[i] = ((state[i] + block[i]) & 0xFF);
            state[i] = (state[i] * 3) & 0xFF;
            state[i] ^= block[i];
        }
    }

    // --- Public Hash API ---

    public static String hash(String input, String salt) {

        String password = salt + input;

        byte[] bytes = password.getBytes(StandardCharsets.UTF_8);

        if (bytes.length == 0) {
            bytes = new byte[]{0};
        }

        int[] state = new int[64];

        state[0] ^= bytes.length & 0xFF;
        state[1] ^= (bytes.length >> 8) & 0xFF;

        int[] block = new int[64];
        Arrays.fill(block, state[0]);

        int len = Math.min(bytes.length, 64);

        for (int i = 0; i < len; i++) {
            block[i] = bytes[i] & 0xFF;
        }

        int[] sbox = initSbox(bytes);

        int extraRounds =
                ((bytes[0] & 0xFF) + (bytes[bytes.length - 1] & 0xFF)) % 255;

        extraRounds %= 1000;

        int numRounds = 10000 + extraRounds;

        for (int i = 0; i < numRounds; i++) {
            round(state, block, sbox, bytes);
        }

        endMix(state, block, sbox);

        StringBuilder hex = new StringBuilder();

        for (int b : state) {
            hex.append(String.format("%02x", b & 0xFF));
        }

        return hex.toString();
    }
}