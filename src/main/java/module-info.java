import alexei.sischin.obfuscatewg.protocol.spi.ProtocolBuilder;
import alexei.sischin.obfuscatewg.protocol.pcc20.sp.PaddedChaCha20Builder;

module obfuscate.wg.protocol.pcc20 {

    requires obfuscate.wg.protocol;

    requires static lombok;

    provides ProtocolBuilder with PaddedChaCha20Builder;
}
