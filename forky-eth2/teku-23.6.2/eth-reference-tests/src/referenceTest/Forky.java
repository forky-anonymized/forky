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

 package tech.pegasys.teku.reference.capella.forky;

 import java.nio.file.Path;
 import org.junit.jupiter.api.DisplayName;
 import org.junit.jupiter.api.Test;
 import tech.pegasys.teku.ethtests.finder.TestDefinition;
 import tech.pegasys.teku.reference.Eth2ReferenceTestCase;
 
 @DisplayName("capella - mainnet - forky")
 public class PLACEHOLDER extends Eth2ReferenceTestCase {
 
   @Test
   @DisplayName("forky")
   void testForky() throws Throwable {
    runReferenceTest(
         new TestDefinition("capella", "mainnet", "forky", "PLACEHOLDER", Path.of("forky/PLACEHOLDER")));
   }
 }
 