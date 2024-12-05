public class SHA1 {

    // SHA-1 constants
    private static final int[] K = {0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6};

    public static byte[] sha1(byte[] input) {
        // Initial state (H)
        int[] H = {
                0x67452301, // H0
                0xefcdab89, // H1
                0x98badcfe, // H2
                0x10325476, // H3
                0xc3d2e1f0  // H4
        };

        int originalLength = input.length;  // Input length in bytes

        // Calculate padded length (must be a multiple of 64 bytes)
        int paddedLength = (originalLength + 8 + 63) & ~63;
        byte[] paddedInput = new byte[paddedLength];

        // Copy original input into padded array
        System.arraycopy(input, 0, paddedInput, 0, originalLength);

        // Append the single 0x80 byte
        paddedInput[originalLength] = (byte) 0x80;

        // Calculate the length in bits
        long lengthInBits = (long) originalLength * 8;

        // Append the length in bits as 64-bit big-endian
        for (int i = 0; i < 8; i++) {
            paddedInput[paddedLength - 8 + i] = (byte) (lengthInBits >>> (8 * (7 - i)));
        }

        // Step 2: Process the input in 512-bit (64-byte) blocks
        for (int offset = 0; offset < paddedInput.length; offset += 64) {
            // Create a block of 80 words (each 32 bits, which is 4 bytes)
            int[] words = new int[80];
            for (int i = 0; i < 16; i++) {
                words[i] = ((paddedInput[offset + i * 4] & 0xFF) << 24) |
                        ((paddedInput[offset + i * 4 + 1] & 0xFF) << 16) |
                        ((paddedInput[offset + i * 4 + 2] & 0xFF) << 8) |
                        (paddedInput[offset + i * 4 + 3] & 0xFF);
            }

            // Extend the 16 words into 80 words
            for (int i = 16; i < 80; i++) {
                words[i] = Integer.rotateLeft(
                        words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16], 1);
            }

            // Initialize the 5 working variables
            int a = H[0];
            int b = H[1];
            int c = H[2];
            int d = H[3];
            int e = H[4];

            // Main SHA-1 loop
            for (int i = 0; i < 80; i++) {
                int f;
                int k;
                if (i < 20) {
                    f = (b & c) | ((~b) & d);
                    k = K[0];
                } else if (i < 40) {
                    f = b ^ c ^ d;
                    k = K[1];
                } else if (i < 60) {
                    f = (b & c) | (b & d) | (c & d);
                    k = K[2];
                } else {
                    f = b ^ c ^ d;
                    k = K[3];
                }

                int temp = Integer.rotateLeft(a, 5) + f + e + k + words[i];
                e = d;
                d = c;
                c = Integer.rotateLeft(b, 30);
                b = a;
                a = temp;
            }

            // Add this chunk's hash to the result so far
            H[0] += a;
            H[1] += b;
            H[2] += c;
            H[3] += d;
            H[4] += e;
        }

        // Step 3: Output the final hash
        byte[] output = new byte[20];  // SHA-1 produces a 160-bit (20-byte) hash
        for (int i = 0; i < 5; i++) {
            int val = H[i];
            output[i * 4] = (byte) (val >>> 24);
            output[i * 4 + 1] = (byte) (val >>> 16);
            output[i * 4 + 2] = (byte) (val >>> 8);
            output[i * 4 + 3] = (byte) val;
        }
        return output;
    }
}
