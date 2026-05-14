package alexei.sischin.obfuscatewg.protocol.pcc20.sp;

import alexei.sischin.obfuscatewg.protocol.spi.ProtocolBuilder;
import alexei.sischin.obfuscatewg.protocol.api.Protocol;
import alexei.sischin.obfuscatewg.protocol.pcc20.PaddedChaCha20;

import java.util.Base64;

public class PaddedChaCha20Builder implements ProtocolBuilder {

    @Override
    public Protocol build(String secretKeyString) {
        try {
            byte[] secretKeyBytes = Base64.getDecoder().decode(secretKeyString);
            return new PaddedChaCha20(secretKeyBytes);
        } catch (Exception e) {
            throw new IllegalStateException("Unexpected error during protocol initialization", e);
        }
    }
}
