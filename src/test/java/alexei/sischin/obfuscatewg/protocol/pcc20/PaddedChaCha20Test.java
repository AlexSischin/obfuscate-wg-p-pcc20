package alexei.sischin.obfuscatewg.protocol.pcc20;

import alexei.sischin.obfuscatewg.protocol.api.Protocol;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.nio.ByteBuffer;
import java.util.HexFormat;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Slf4j
class PaddedChaCha20Test {

    private static final byte[] SECRET_KEY = new byte[32];

    @SneakyThrows
    @MethodSource("encryptedPackets")
    @ParameterizedTest
    void obfuscate_givenValidInput_generatesExpectedBytes(
            String rawDataHex,
            String encryptedDataHex,
            int bufSize
    ) {
        byte[] rawData = hexToBytes(rawDataHex);
        ByteBuffer buffer = ByteBuffer.allocate(bufSize);
        buffer.put(rawData).flip();

        Protocol victim = new PaddedChaCha20(SECRET_KEY);
        victim.obfuscate(buffer);

        byte[] result = new byte[buffer.remaining()];
        buffer.get(result);
        String resultHex = bytesToHex(result);
        assertThat(resultHex).isEqualToIgnoringWhitespace(encryptedDataHex);
    }

    @SneakyThrows
    @MethodSource("encryptedPacketsWithRawDataOffsets")
    @ParameterizedTest
    void obfuscate_givenValidInputWithPositionOffset_generatesSameExpectedBytes(
            String rawDataHex,
            String encryptedDataHex,
            int bufSize,
            int positionOffset
    ) {
        byte[] rawData = hexToBytes(rawDataHex);
        ByteBuffer buffer = ByteBuffer.allocate(bufSize + positionOffset);
        buffer.position(positionOffset);
        buffer.put(rawData).flip().position(positionOffset);

        Protocol victim = new PaddedChaCha20(SECRET_KEY);
        victim.obfuscate(buffer);

        byte[] result = new byte[buffer.remaining()];
        buffer.get(result);
        String resultHex = bytesToHex(result);
        assertThat(resultHex).isEqualToIgnoringWhitespace(encryptedDataHex);
    }

    @SneakyThrows
    @MethodSource("encryptedPacketsWithRawDataOffsets")
    @ParameterizedTest
    void obfuscate_givenValidInputWithArrayOffset_generatesSameExpectedBytes(
            String rawDataHex,
            String encryptedDataHex,
            int bufSize,
            int arrayOffset
    ) {
        byte[] rawData = hexToBytes(rawDataHex);
        ByteBuffer buffer = ByteBuffer.allocate(bufSize + arrayOffset);
        buffer = buffer.slice(arrayOffset, bufSize);
        buffer.put(rawData).flip();

        Protocol victim = new PaddedChaCha20(SECRET_KEY);
        victim.obfuscate(buffer);

        byte[] result = new byte[buffer.remaining()];
        buffer.get(result);
        String resultHex = bytesToHex(result);
        assertThat(resultHex).isEqualToIgnoringWhitespace(encryptedDataHex);
    }

    @SneakyThrows
    @MethodSource("encryptedPackets")
    @ParameterizedTest
    void deobfuscate_givenValidInput_generatesExpectedBytes(
            String rawDataHex,
            String encryptedDataHex,
            int bufSize
    ) {
        byte[] encryptedData = hexToBytes(encryptedDataHex);
        ByteBuffer buffer = ByteBuffer.allocate(bufSize);
        buffer.put(encryptedData).flip();

        Protocol victim = new PaddedChaCha20(SECRET_KEY);
        victim.deobfuscate(buffer);

        byte[] result = new byte[buffer.remaining()];
        buffer.get(result);
        String resultHex = bytesToHex(result);
        assertThat(resultHex).isEqualToIgnoringWhitespace(rawDataHex);
    }

    @SneakyThrows
    @MethodSource("encryptedPacketsWithEncryptedDataOffsets")
    @ParameterizedTest
    void deobfuscate_givenValidInputWithPositionOffset_generatesSameExpectedBytes(
            String rawDataHex,
            String encryptedDataHex,
            int bufSize,
            int positionOffset
    ) {
        byte[] encryptedData = hexToBytes(encryptedDataHex);
        ByteBuffer buffer = ByteBuffer.allocate(bufSize);
        buffer.position(positionOffset);
        buffer.put(encryptedData).flip().position(positionOffset);

        Protocol victim = new PaddedChaCha20(SECRET_KEY);
        victim.deobfuscate(buffer);

        byte[] result = new byte[buffer.remaining()];
        buffer.get(result);
        String resultHex = bytesToHex(result);
        assertThat(resultHex).isEqualToIgnoringWhitespace(rawDataHex);
    }

    @SneakyThrows
    @MethodSource("encryptedPacketsWithEncryptedDataOffsets")
    @ParameterizedTest
    void deobfuscate_givenValidInputWithArrayOffset_generatesSameExpectedBytes(
            String rawDataHex,
            String encryptedDataHex,
            int bufSize,
            int arrayOffset
    ) {
        byte[] encryptedData = hexToBytes(encryptedDataHex);
        ByteBuffer buffer = ByteBuffer.allocate(bufSize + arrayOffset);
        buffer = buffer.slice(arrayOffset, bufSize);
        buffer.put(encryptedData).flip();

        Protocol victim = new PaddedChaCha20(SECRET_KEY);
        victim.deobfuscate(buffer);

        byte[] result = new byte[buffer.remaining()];
        buffer.get(result);
        String resultHex = bytesToHex(result);
        assertThat(resultHex).isEqualToIgnoringWhitespace(rawDataHex);
    }

    static byte[] hexToBytes(String hex) {
        return HexFormat.of().parseHex(hex.replaceAll("\\s+", ""));
    }

    static String bytesToHex(byte[] bytes) {
        HexFormat hex = HexFormat.ofDelimiter(" ");
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bytes.length; i += 16) {
            int end = Math.min(i + 16, bytes.length);
            if (i > 0) {
                sb.append('\n');
            }
            sb.append(hex.formatHex(bytes, i, end));
        }
        return sb.toString();
    }

    static Stream<Arguments> encryptedPackets() {
        return Stream.of(
                // Handshake initiation (1)
                Arguments.of(
                        """
                        01 00 00 00 a0 87 7e 97 cf fc f2 ab 64 9d cc 48
                        5f de 6b 7a 6e 04 ed d2 d1 46 44 92 84 f3 32 64
                        29 c8 30 99 0d ec 1c 4e 77 46 7d 89 46 91 5d b8
                        fc a8 7b a6 54 4f 2c 1c e7 a9 b8 46 a7 bb bf 78
                        19 87 b8 08 a4 5e 2e 6a 0c 70 b1 cd a6 b5 44 7a
                        c2 e9 17 bf e1 04 84 fb 03 9f 77 d7 22 39 aa 05
                        77 db ca a6 11 13 3a 99 fe a8 c1 63 bf ce 6c 92
                        b6 8e 1b 32 89 1a 5e 76 5c 7d eb db 88 30 3c 86
                        4b 01 9b 5b 00 00 00 00 00 00 00 00 00 00 00 00
                        00 00 00 00
                        """,
                        """
                        cf fc f2 ab 64 9d cc 48 5f de 6b 7a da 56 fe 94
                        45 bd 6f 72 e1 9b b3 79 4d d9 ae 36 be 2d 4c 2c
                        16 0b 09 d8 3a ea e5 f8 53 29 55 54 9d d0 b4 36
                        0b 65 ac 2c c8 78 96 7b bd d5 47 3b 1f f5 06 97
                        c4 88 12 f8 ba de ca 0d a8 85 37 7e 0c 38 8c 9c
                        9b 16 5c c9 e3 6d eb f7 48 b4 5b 6e ea 9c 48 f0
                        35 93 11 bb d9 4f ad d7 21 c6 2b 5a 20 e1 85 d7
                        9d 48 59 22 03 15 0e 17 02 28 4d d4 6d d3 72 d5
                        84 37 a4 7a cc 03 0d e7 75 49 d6 16 20 67 ea 96
                        a2 e0 7b 39 0d bf 5d 66 f2 f7 53 ef 0c e3 7e 5d
                        ea 32 48 c8 59 4c a8 64 db 92 52 bb 8e 78 4a 64
                        a6 cc 2d ed 86 77 a0 4e b3 1b 4e 87 59 fa 61 53
                        70 e5 82 1e a1 8c c9 c0 79 2c 39 2d 09 68 ae 89
                        2f 47 88 a0 25 de 4b 0c 64 fa bb 82 fc cf 02 ab
                        6c 1a 15 e5 e0 0a 7f d1 8d 78 5b d9 e2 1d 6d 87
                        a7 b3 32 43 44 86 72 01 7f 2d 1a 55 dc d8 6a b7
                        8c bf 9d 0b e8 53 c9 79 d7 56 29 6e e3 e5 52 11
                        6a cf ce c0 77 8d f6 fa d4 83 89 34 1b 5c 62 3c
                        1c 7c 09 2c b5 f3 5c 4c 06 eb 94 e2 b1 3a 2f 25
                        f1 9d 79 bf 4f 81 f1 ba a4 63 87 08 10 99 85 b2
                        32 ec 2b 32 c7
                        """,
                        1420
                ),
                // Handshake response (2)
                Arguments.of(
                        """
                        02 00 00 00 78 31 ec 37 a0 87 7e 97 f7 f6 44 49
                        5f 3d 9f 73 27 34 f2 6a e4 ea f1 39 cc c3 d3 df
                        cc ca 0b 34 db ba 50 a1 29 d5 f8 40 2c 3b 76 78
                        ce e1 b0 7c 0e 43 83 11 a9 b4 02 fb fb a6 79 7c
                        50 01 6f 9e 62 50 d0 83 1b f6 3f 4e 00 00 00 00
                        00 00 00 00 00 00 00 00 00 00 00 00
                        """,
                        """
                        f7 f6 44 49 5f 3d 9f 73 27 34 f2 6a ca 0a 30 e1
                        85 52 bc 0e 81 27 04 99 1c e8 1a 78 51 bd f4 8d
                        9b b4 7d bd 4a 68 9b 87 1c 5c 65 e1 8e 07 eb ea
                        4c 73 1a 4d 6e 3e 36 f7 98 13 9c aa a2 75 61 2f
                        88 a5 c2 48 16 de 4b 5b 89 c5 fc 33 f1 ba 3e c2
                        99 a1 08 6c 6b 2c 96 bc 6e e0 57 f6 ad 2e d7 60
                        03 76 eb 4f 71 bf 5a 06 af a1 25 05 5e 7b 36 73
                        13 e2 a5 c6 ca 6e 22 c2 cd f5 0e b4 57 6c c0 94
                        8e d9 b6 7f 3f d2 57 15 c2 29 6f c4 1e c4 65 4e
                        7d c8 ff 7b d4 78 29 ce ab 74 64 77 ec 1e 4b df
                        49 ff fb fc 69 6b 0b 6b 46 53 32
                        """,
                        1420
                ),
                // Transport data (4): Keepalive
                Arguments.of(
                        """
                        04 00 00 00 78 31 ec 37 00 00 00 00 00 00 00 00
                        41 64 ad 73 75 7d 97 00 f9 94 f7 a5 96 cd 4a bd
                        """,
                        """
                        41 64 ad 73 75 7d 97 00 f9 94 f7 a5 93 48 3c fb
                        b0 1b b3 74 36 41 a5 bc c7 3b 8d 9a 9e ff bb 0c
                        d9 c7 87 2c 47 f0 6f f1 35 b5 46 9f a2 c8 4f 6d
                        88 12 03 7e a8 73 fa 0b b2 b9 e6 3c 11 b8 91 bc
                        ea 97 bf 3e 66 70 09 48 2c f9 72 fc f8 8d 88 34
                        4d 0d 98 b0 56 aa 78 40 13 92 ed b2 80 a7 e4 a5
                        ff 6f 63 c6 81 f9 9d
                        """,
                        1420
                ),
                // Transport data (4): Data
                Arguments.of(
                        """
                        04 00 00 00 f0 48 74 01 01 00 00 00 00 00 00 00
                        54 d8 b3 d3 83 d9 0f ad 48 ee 6d 30 34 bf a3 1b
                        7e d0 38 a9 60 f9 fa 6a f6 1c f0 0f b1 10 f7 ce
                        df 10 70 2b 80 14 6a 88 1c 5a 8c 50 4d 10 1a c6
                        1f 0b 5c 73 6a 93 8b e7 f4 bf 4b c1 8f 71 39 ad
                        e8 06 84 dc d7 ec 7b 31 b2 4e 7b ac d4 9f bd fe
                        """,
                        """
                        54 d8 b3 d3 83 d9 0f ad 48 ee 6d 30 80 5d 57 4a
                        53 61 d9 c3 da a1 cc 8a 4b 14 e9 a7 b2 25 55 95
                        da a3 82 d0 00 6a 7d 06 f7 4a 02 cf 7f 91 7f 04
                        52 44 28 b4 d5 ae 4b 0b cd 4c c1 97 75 d3 58 97
                        0e 1f 15 cc 3d 54 64 aa 90 19 fd ab 84 d7 ca ab
                        88 d0 df fb db 94 4a 26 84 01 3a b3 97 d4 a4 28
                        f2 9e db cf c5 bd 2d 23 5f eb 1b 0e db 33 2a c2
                        33 8b a9 c6 94 cd 60 31 19 af 0e 54 f2 98 33 e0
                        65 28 ef 77 af ee 8c a2 2a de e8 90 c7 89 d6 21
                        0a 2e 45 9a 98 6c f5 68 be 4d 25 22 0d 0a 64 9d
                        54 e1 a9 f4 b9 c4 39 c2 ab a3 fe c0 51 43 1b e7
                        ac 62 6a 5a 6e 22 58 1b 75 02 21 27 85 0a a8 b3
                        35 57 27 68 bf 7a 94 f5 55 25 ef a2 55 10 9a 86
                        e6 d9 ef 84 c6 60 66 93 46 98 17 44 9b 42 38 c2
                        67 a4 e5 80 d0 1f db 6a f7 37 d4 76 42 bc b2 bb
                        5e c4 08 0c 25 bf ed ce d2 fe 6c a2 84 f1 da 9c
                        c1 a5 71 af 84 ad 62 04 92 00 9b 53 dc 5e ca dc
                        28 a8 ca 80 2c
                        """,
                        1420
                )
        );
    }

    static Stream<Arguments> encryptedPacketsWithRawDataOffsets() {
        String rawPacketHex = """
            04 00 00 00 78 31 ec 37 00 00 00 00 00 00 00 00
            41 64 ad 73 75 7d 97 00 f9 94 f7 a5 96 cd 4a bd
            """;
        String encryptedPacketHex = """
            41 64 ad 73 75 7d 97 00 f9 94 f7 a5 93 0c 3c fb
            b0 1b b3 74 36 41 a5 bc c7 3b 8d 9a 9e ff bb 0c
            d9 c7 87
            """;
        int minBufferSize = (int) Pattern.compile("\\w{2}").matcher(rawPacketHex).results().count();
        return Stream.of(
                Arguments.of(rawPacketHex, encryptedPacketHex, minBufferSize + 8, 0),
                Arguments.of(rawPacketHex, encryptedPacketHex, minBufferSize + 8, 1),
                Arguments.of(rawPacketHex, encryptedPacketHex, minBufferSize + 8, 2),
                Arguments.of(rawPacketHex, encryptedPacketHex, minBufferSize + 8, 4),
                Arguments.of(rawPacketHex, encryptedPacketHex, minBufferSize + 8, 8)
        );
    }

    static Stream<Arguments> encryptedPacketsWithEncryptedDataOffsets() {
        String rawPacketHex = """
            04 00 00 00 78 31 ec 37 00 00 00 00 00 00 00 00
            41 64 ad 73 75 7d 97 00 f9 94 f7 a5 96 cd 4a bd
            """;
        String encryptedPacketHex = """
            41 64 ad 73 75 7d 97 00 f9 94 f7 a5 93 0c 3c fb
            b0 1b b3 74 36 41 a5 bc c7 3b 8d 9a 9e ff bb 0c
            d9 c7 87
            """;
        int minBufferSize = (int) Pattern.compile("\\w{2}").matcher(encryptedPacketHex).results().count();
        return Stream.of(
                Arguments.of(rawPacketHex, encryptedPacketHex, minBufferSize + 8, 0),
                Arguments.of(rawPacketHex, encryptedPacketHex, minBufferSize + 8, 1),
                Arguments.of(rawPacketHex, encryptedPacketHex, minBufferSize + 8, 2),
                Arguments.of(rawPacketHex, encryptedPacketHex, minBufferSize + 8, 4),
                Arguments.of(rawPacketHex, encryptedPacketHex, minBufferSize + 8, 8)
        );
    }
}
