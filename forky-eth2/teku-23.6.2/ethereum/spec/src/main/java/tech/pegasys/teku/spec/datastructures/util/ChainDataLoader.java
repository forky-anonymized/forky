/*
 * Copyright ConsenSys Software Inc., 2022
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

package tech.pegasys.teku.spec.datastructures.util;

import java.io.FileNotFoundException;
import java.io.IOException;
import tech.pegasys.teku.infrastructure.io.resource.ResourceLoader;
import tech.pegasys.teku.spec.Spec;
import tech.pegasys.teku.spec.datastructures.state.beaconstate.BeaconState;

public class ChainDataLoader {
  public static BeaconState loadState(final Spec spec, final String source) throws IOException {
    return spec.deserializeBeaconState(
        ResourceLoader.urlOrFile("application/octet-stream")
            .loadBytes(source)
            .orElseThrow(() -> new FileNotFoundException("Not found")));
  }
}
