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
