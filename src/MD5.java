public class MD5 {

    private static final long[] SINE_TABLE = new long[64];

    static {
        for (int i = 0; i < 64; i++) {
            // 用 sin(i + 1) 计算，确保计算值是长整型（long），并且乘以 2^32 来生成 32 位整数
            SINE_TABLE[i] = (long) (Math.floor(Math.abs(Math.sin(i + 1)) * 0x100000000L));
        }
    }
    private static final int[] SINE_TABLE_INT = new int[64];
    static {
        for (int i = 0; i < 64; i++) {
            // 用 sin(i + 1) 计算，确保计算值是长整型（long），并且乘以 2^32 来生成 32 位整数
            SINE_TABLE_INT[i] = (int)SINE_TABLE[i];
        }
    }

    // MD5 Hash computation

    public static byte[] md5(byte[] input) {
        // Initial state (buffer)
        int[] buffer = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476};

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

        // Append the length in bits as 64-bit little-endian
        for (int i = 0; i < 8; i++) {
            paddedInput[paddedLength - 8 + i] = (byte) (lengthInBits >>> (8 * i));
        }

        // Step 2: Process the input in 512-bit (64-byte) blocks
        for (int offset = 0; offset < paddedInput.length; offset += 64) {
            // Create a block of 16 words (each 32 bits, which is 4 bytes)
            int[] words = new int[16];
            for (int i = 0; i < 16; i++) {
                words[i] = (paddedInput[offset + i * 4] & 0xFF) |
                        ((paddedInput[offset + i * 4 + 1] & 0xFF) << 8) |
                        ((paddedInput[offset + i * 4 + 2] & 0xFF) << 16) |
                        ((paddedInput[offset + i * 4 + 3] & 0xFF) << 24);
            }

            int[] state = buffer.clone();

            int[] SHIFT_AMOUNTS = {7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21};

            // Step 3: Main MD5 loop (64 rounds)
            for (int i = 0; i < 64; i++) {
                int div16 = i / 16;
                int f = 0;
                int g = 0;

                // MD5 round function
                if (div16 == 0) {
                    f = (state[1] & state[2]) | (~state[1] & state[3]);
                    g = i;
                } else if (div16 == 1) {
                    f = (state[3] & state[1]) | (~state[3] & state[2]);
                    g = (5 * i + 1) % 16;
                } else if (div16 == 2) {
                    f = state[1] ^ state[2] ^ state[3];
                    g = (3 * i + 5) % 16;
                } else {
                    f = state[2] ^ (state[1] | ~state[3]);
                    g = (7 * i) % 16;
                }

                int temp = state[3];
                state[3] = state[2];
                state[2] = state[1];
                int shiftAmount = SHIFT_AMOUNTS[(div16 * 4 + i % 4)];
                state[1] = state[1] + Integer.rotateLeft(state[0] + f + SINE_TABLE_INT[i] + words[g], shiftAmount);
                state[0] = temp;
            }

            // Add the current block's hash to the overall buffer state
            for (int i = 0; i < 4; i++) {
                buffer[i] += state[i];
            }
        }

        // Step 4: Output the final hash
        byte[] output = new byte[16];  // MD5 produces a 128-bit (16-byte) hash
        for (int i = 0; i < 4; i++) {
            int val = buffer[i];
            output[i * 4] = (byte) (val & 0xFF);
            output[i * 4 + 1] = (byte) ((val >> 8) & 0xFF);
            output[i * 4 + 2] = (byte) ((val >> 16) & 0xFF);
            output[i * 4 + 3] = (byte) ((val >> 24) & 0xFF);
        }
        return output;
    }
}
