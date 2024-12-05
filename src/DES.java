class DES {

    private static final int[] IP = {  // Initial Permutation
            58, 50, 42, 34, 26, 18, 10, 2,
            60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6,
            64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17, 9, 1,
            59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5,
            63, 55, 47, 39, 31, 23, 15, 7
    };

    private static final int[] IP_1 = {  // Inverse Initial Permutation
            40, 8, 48, 16, 56, 24, 64, 32,
            39, 7, 47, 15, 55, 23, 63, 31,
            38, 6, 46, 14, 54, 22, 62, 30,
            37, 5, 45, 13, 53, 21, 61, 29,
            36, 4, 44, 12, 52, 20, 60, 28,
            35, 3, 43, 11, 51, 19, 59, 27,
            34, 2, 42, 10, 50, 18, 58, 26,
            33, 1, 41, 9, 49, 17, 57, 25
    };

    private static final int[] PC1 = {  // Permuted Choice 1
            57, 49, 41, 33, 25, 17, 9,
            1, 58, 50, 42, 34, 26, 18,
            10, 2, 59, 51, 43, 35, 27,
            19, 11, 3, 60, 52, 44, 36,
            63, 55, 47, 39, 31, 23, 15,
            7, 62, 54, 46, 38, 30, 22,
            14, 6, 61, 53, 45, 37, 29,
            21, 13, 5, 28, 20, 12, 4
    };

    private static final int[] PC2 = {  // Permuted Choice 2
            14, 17, 11, 24, 1, 5,
            3, 28, 15, 6, 21, 10,
            23, 19, 12, 4, 26, 8,
            16, 7, 27, 20, 13, 2,
            41, 52, 31, 37, 47, 55,
            30, 40, 51, 45, 33, 48,
            44, 49, 39, 56, 34, 53,
            46, 42, 50, 36, 29, 32
    };

    private static final int[] P = {  // P-Box
            16, 7, 20, 21,
            29, 12, 28, 17,
            1, 15, 23, 26,
            5, 18, 31, 10,
            2, 8, 24, 14,
            32, 27, 3, 9,
            19, 13, 30, 6,
            22, 11, 4, 25
    };

    private static final int[][][] S = {  // S-Boxes
            { // S box 1
                    {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
                    {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
                    {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
                    {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}
            },
            { // S box 2
                    {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
                    {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
                    {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
                    {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}
            },
            { // S box 3
                    {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
                    {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
                    {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
                    {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}
            },
            { // S box 4
                    {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
                    {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
                    {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
                    {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}
            },
            { // S box 5
                    {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
                    {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
                    {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
                    {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}
            },
            { // S box 6
                    {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
                    {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
                    {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
                    {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}
            },
            { // S box 7
                    {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
                    {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
                    {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
                    {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}
            },
            {
                    {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
                    {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
                    {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
                    {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}
            }// Additional S-Boxes omitted for brevity
    };

    /**
     * Encrypts a 64-bit block using DES.
     * @param plaintext 8-byte input block to encrypt
     * @param key 8-byte encryption key
     * @return 8-byte encrypted block
     */
    public static byte[] encrypt(byte[] plaintext, byte[] key) {
        // 1. Key generation
        byte[][] subKeys = generateSubkeys(key);

        // 2. Initial Permutation (IP)
        byte[] permuted = permute(plaintext, IP);

        // 3. Feistel Network (16 rounds)
        byte[] left = new byte[4];
        byte[] right = new byte[4];
        System.arraycopy(permuted, 0, left, 0, 4);
        System.arraycopy(permuted, 4, right, 0, 4);

        for (int round = 0; round < 16; round++) {
            byte[] temp = right.clone();
            right = xor(left, feistelFunction(right, subKeys[round]));
            left = temp;
        }

        // 4. Final swap before final permutation
        byte[] combined = new byte[8];
        System.arraycopy(right, 0, combined, 0, 4);
        System.arraycopy(left, 0, combined, 4, 4);

        // 5. Final Permutation (IP^-1)
        return permute(combined, IP_1);
    }

    /**
     * Generates 16 subkeys from the main key
     * @param key Original 64-bit key
     * @return Array of 16 48-bit round keys
     */
    private static byte[][] generateSubkeys(byte[] key) {
        // Perform PC1 permutation to get 56-bit key (7 bytes)
        byte[] permutedKey = permute(key, PC1);

        // Ensure permutedKey is exactly 7 bytes
        if (permutedKey.length != 7) {
            throw new IllegalStateException("PC1 permutation failed to produce 56 bits");
        }

        // Split the permuted key into two 28-bit halves (4 bytes each)
        byte[] left = new byte[4];  // 28 bits
        byte[] right = new byte[4]; // 28 bits

        System.arraycopy(permutedKey, 0, left, 0, 4); // First 28 bits
        System.arraycopy(permutedKey, 3, right, 0, 4); // Last 28 bits, shifted by 1 byte

        byte[][] subKeys = new byte[16][6]; // 16 subkeys, each 6 bytes (48 bits)

        for (int round = 0; round < 16; round++) {
            // Perform left circular shifts on the halves
            left = leftShift(left, round);
            right = leftShift(right, round);

            // Combine the left and right halves into a 56-bit key
            byte[] combinedKey = concatenate(left, right);

            // Perform PC2 permutation to get a 48-bit subkey
            subKeys[round] = permute(combinedKey, PC2);
        }

        return subKeys;
    }



    /**
     * Feistel Function implementation
     * @param right 32-bit right half of the block
     * @param subKey 48-bit round key
     * @return 32-bit processed output
     */
    private static byte[] feistelFunction(byte[] right, byte[] subKey) {
        byte[] expanded = expand(right);
        byte[] xored = xor(expanded, subKey);
        byte[] substituted = sBoxSubstitution(xored);
        return permute(substituted, P);
    }


    private static final int[] E = {
            32, 1, 2, 3, 4, 5,  4, 5, 6, 7, 8, 9,
            8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
            16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
            24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1
    };

    private static byte[] expand(byte[] input) {
        byte[] expanded = new byte[6];  // 48 bits = 6 bytes
        int bitIndex = 0;

        for (int i = 0; i < 48; i++) {
            // Get the bit position from the Expansion table (E)
            int position = E[i] - 1;  // E is 1-based index, so subtract 1

            // Determine which byte and bit within the byte to extract
            int byteIndex = position / 8;
            int bitInByte = position % 8;

            // Extract the bit and set it in the expanded array
            int bit = (input[byteIndex] >> (7 - bitInByte)) & 1;
            expanded[bitIndex / 8] |= (bit << (7 - (bitIndex % 8)));

            bitIndex++;
        }

        return expanded;
    }

    /**
     * S-box substitution
     * @param input 48-bit input
     * @return 32-bit output after S-box substitution
     */
    private static byte[] sBoxSubstitution(byte[] input) {
        byte[] output = new byte[4];
        for (int box = 0; box < 8; box++) {
            int sixBits = ((input[box / 2] >>> (4 * (1 - box % 2))) & 0x3F);
            int row = ((sixBits & 0x20) >> 4) | (sixBits & 0x01);
            int col = (sixBits & 0x1E) >> 1;
            int substituted = S[box][row][col];
            output[box / 2] |= (substituted << (4 * (1 - box % 2)));
        }
        return output;
    }

    /**
     * Generic permutation method
     * @param input Input block to permute
     * @param permutationBox Permutation box
     * @return Permuted output
     */
    private static byte[] permute(byte[] input, int[] permutationBox) {
        int outputLength = (permutationBox.length + 7) / 8; // Number of bytes needed
        byte[] output = new byte[outputLength]; // Create output array of correct size

        for (int i = 0; i < permutationBox.length; i++) {
            // Get bit position from the permutation table
            int bitPosition = permutationBox[i] - 1; // Convert to 0-based index

            // Find source byte and bit position
            int sourceByte = bitPosition / 8;
            int sourceBit = bitPosition % 8;

            // Find destination byte and bit position
            int destByte = i / 8;
            int destBit = 7 - (i % 8);

            // Extract bit and set in the output
            int bit = (input[sourceByte] >>> (7 - sourceBit)) & 1;
            output[destByte] |= (bit << destBit);
        }

        return output;
    }


    /**
     * Performs left circular shift
     * @param round Current round (determines shift amount)
     * @return Shifted value
     */
    private static byte[] leftShift(byte[] input, int round) {
        int[] shiftAmounts = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};
        int shift = shiftAmounts[round];
        int totalBits = input.length * 8;
        byte[] output = new byte[input.length];
        for (int i = 0; i < totalBits; i++) {
            int newIndex = (i + shift) % totalBits;
            int bit = (input[i / 8] >>> (7 - (i % 8))) & 0x01;
            output[newIndex / 8] |= (bit << (7 - (newIndex % 8)));
        }
        return output;
    }

    private static byte[] xor(byte[] a, byte[] b) {
        byte[] result = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            result[i] = (byte) (a[i] ^ b[i]);
        }
        return result;
    }

    private static byte[] concatenate(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }

    /**
     * Decryption method (essentially same as encryption with reversed keys)
     * @param ciphertext 64-bit block to decrypt
     * @param key 64-bit encryption key
     * @return 64-bit decrypted block
     */
    public static byte[] decrypt(byte[] ciphertext, byte[] key) {
        byte[][] subKeys = generateSubkeys(key);
        byte[] permuted = permute(ciphertext, IP);

        byte[] left = new byte[4];
        byte[] right = new byte[4];
        System.arraycopy(permuted, 0, left, 0, 4);
        System.arraycopy(permuted, 4, right, 0, 4);

        for (int round = 15; round >= 0; round--) {
            byte[] temp = right.clone();
            right = xor(left, feistelFunction(right, subKeys[round]));
            left = temp;
        }

        byte[] combined = new byte[8];
        System.arraycopy(right, 0, combined, 0, 4);
        System.arraycopy(left, 0, combined, 4, 4);

        return permute(combined, IP_1);
    }

}