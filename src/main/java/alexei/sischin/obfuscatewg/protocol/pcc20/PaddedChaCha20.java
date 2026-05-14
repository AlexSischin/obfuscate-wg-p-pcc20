/*
 * Copyright 2026 Alexei Sischin.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package alexei.sischin.obfuscatewg.protocol.pcc20;

import alexei.sischin.obfuscatewg.protocol.api.Protocol;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class PaddedChaCha20 implements Protocol {

    private static final int NONCE_SIZE = 12;
    private static final int PADDING_SIZE_OFFSET = 1;
    private static final byte PADDING_CONTENT = 0;

    private final SecretKey secretKey;

    private final ThreadLocal<Cipher> cipherTl = new ThreadLocal<>();
    private final ThreadLocal<MessageDigest> messageDigestTl = new ThreadLocal<>();
    private final ThreadLocal<ByteBuffer> nonceBufferTl = new ThreadLocal<>();

    public PaddedChaCha20(byte[] secretKey) throws IllegalArgumentException {
        this.secretKey = new SecretKeySpec(secretKey, 0, secretKey.length, "ChaCha20");
    }

    @Override
    public void obfuscate(ByteBuffer data) {
        try {
            int paddingMaxSize = data.capacity() - data.limit();
            int paddingSize = calculatePaddingSize(paddingMaxSize);
            addPadding(data, paddingSize);
            putPaddingSize(data, paddingSize);

            WgPacketType type = detectType(data, 0);
            int nonceOffset = type.getNonceOffset();
            ByteBuffer nonce = getNonceCopy(data, nonceOffset);
            shiftChunk(data, 0, nonceOffset, nonce.remaining());
            putNonce(data, nonce, 0);

            ByteBuffer cipherSlice = data.slice(
                    data.position() + nonce.remaining(),
                    data.remaining() - nonce.remaining()
            );
            ChaCha20ParameterSpec parameterSpec = buildParameterSpec(nonce.duplicate());
            Cipher cipher = getOrCreateCipher();
            cipher.init(Cipher.ENCRYPT_MODE, this.secretKey, parameterSpec, null);
            cipher.update(cipherSlice, cipherSlice.duplicate());
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to obfuscate data", e);
        }
    }

    @Override
    public void deobfuscate(ByteBuffer data) {
        try {
            ByteBuffer nonce = getNonceCopy(data, 0);

            ByteBuffer cipherSlice = data.slice(
                    data.position() + nonce.remaining(),
                    data.remaining() - nonce.remaining()
            );
            ChaCha20ParameterSpec parameterSpec = buildParameterSpec(nonce.duplicate());
            Cipher cipher = getOrCreateCipher();
            cipher.init(Cipher.DECRYPT_MODE, this.secretKey, parameterSpec, null);
            cipher.doFinal(cipherSlice, cipherSlice.duplicate());

            WgPacketType type = detectType(data, nonce.remaining());
            int nonceOffset = type.getNonceOffset();
            shiftChunk(data, nonce.remaining(), nonceOffset, -nonce.remaining());
            putNonce(data, nonce, nonceOffset);

            int paddingSize = getPaddingSize(data);
            removePadding(data, paddingSize);
            clearPaddingSize(data);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to deobfuscate data", e);
        }
    }

    private WgPacketType detectType(ByteBuffer data, int offset) {
        int i = data.position() + offset;
        int typeCode = data.get(i);
        return WgPacketType.fromCode(typeCode);
    }

    private ByteBuffer getNonceCopy(ByteBuffer data, int offset) {
        ByteBuffer nonce = getOrAllocateNonceBuffer();
        int i = data.position() + offset;
        ByteBuffer dataNonce = data.slice(i, nonce.limit());
        return nonce.put(dataNonce).flip();
    }

    private void shiftChunk(ByteBuffer data, int position, int length, int shift) {
        int srcPos = data.arrayOffset() + data.position() + position;
        int destPos = srcPos + shift;
        System.arraycopy(data.array(), srcPos, data.array(), destPos, length);
    }

    private void putNonce(ByteBuffer data, ByteBuffer nonce, int offset) {
        int srcPos = nonce.arrayOffset() + nonce.position();
        int destPos = data.arrayOffset() + data.position() + offset;
        int length = nonce.remaining();
        System.arraycopy(nonce.array(), srcPos, data.array(), destPos, length);
    }

    private void putPaddingSize(ByteBuffer data, int value) {
        int i = data.position() + PADDING_SIZE_OFFSET;
        data.put(i, (byte) value);
    }

    private int getPaddingSize(ByteBuffer data) {
        int i = data.position() + PADDING_SIZE_OFFSET;
        return Byte.toUnsignedInt(data.get(i));
    }

    private void clearPaddingSize(ByteBuffer data) {
        int i = data.position() + PADDING_SIZE_OFFSET;
        data.put(i, (byte) 0);
    }

    private int calculatePaddingSize(int max) throws NoSuchAlgorithmException {
        if (max == 0) {
            return 0;
        }
        MessageDigest md = getOrCreateMessageDigest();
        md.update(this.secretKey.getEncoded());
        md.update((byte) max);
        byte[] hash = md.digest();
        return Byte.toUnsignedInt(hash[0]) % max;
    }

    private void addPadding(ByteBuffer data, int paddingSize) {
        int dataEndIndex = data.limit();
        data.limit(dataEndIndex + paddingSize);
        for (int i = 0; i < paddingSize; i++) {
            data.put(dataEndIndex + i, PADDING_CONTENT);
        }
    }

    private void removePadding(ByteBuffer data, int paddingSize) {
        int dataEndIndex = data.limit() - paddingSize;
        data.limit(dataEndIndex);
    }

    private MessageDigest getOrCreateMessageDigest() throws NoSuchAlgorithmException {
        MessageDigest messageDigest = this.messageDigestTl.get();
        if (messageDigest == null) {
            messageDigest = MessageDigest.getInstance("SHA-256");
            this.messageDigestTl.set(messageDigest);
        }
        return messageDigest;
    }

    private Cipher getOrCreateCipher() throws NoSuchPaddingException, NoSuchAlgorithmException {
        Cipher cipher = this.cipherTl.get();
        if (cipher == null) {
            cipher = Cipher.getInstance("ChaCha20");
            this.cipherTl.set(cipher);
        }
        return cipher;
    }

    private ByteBuffer getOrAllocateNonceBuffer() {
        ByteBuffer nonce = nonceBufferTl.get();
        if (nonce == null) {
            nonce = ByteBuffer.allocate(NONCE_SIZE);
            nonceBufferTl.set(nonce);
        }
        return nonce.clear();
    }

    private ChaCha20ParameterSpec buildParameterSpec(ByteBuffer nonce) {
        ByteBuffer nonceBuffer = getOrAllocateNonceBuffer();
        nonce.get(nonceBuffer.array());
        return new ChaCha20ParameterSpec(nonceBuffer.array(), 0);
    }

    @Getter
    @RequiredArgsConstructor
    private enum WgPacketType {
        HANDSHAKE_REQUEST(0x01, 8),
        HANDSHAKE_RESPONSE(0x02, 12),
        COOKIE_REPLY(0x03, 8),
        DATA(0x04, 16);

        private final int code;
        private final int nonceOffset;

        public static WgPacketType fromCode(int code) {
            return Arrays.stream(WgPacketType.values())
                    .filter(t -> t.code == code)
                    .findAny()
                    .orElseThrow(() -> new IllegalArgumentException("Unexpected code: %s".formatted(code)));
        }
    }
}
