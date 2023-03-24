/*
 * Copyright (C) 2023 DANS - Data Archiving and Networked Services (info@dans.knaw.nl)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package nl.knaw.dans.bagit.verify;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Security;
import java.util.Arrays;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import nl.knaw.dans.bagit.TempFolderTest;
import nl.knaw.dans.bagit.TestUtils;
import nl.knaw.dans.bagit.domain.Bag;
import nl.knaw.dans.bagit.domain.Manifest;
import nl.knaw.dans.bagit.exceptions.CorruptChecksumException;
import nl.knaw.dans.bagit.exceptions.FileNotInManifestException;
import nl.knaw.dans.bagit.exceptions.UnsupportedAlgorithmException;
import nl.knaw.dans.bagit.exceptions.VerificationException;
import nl.knaw.dans.bagit.hash.StandardSupportedAlgorithms;
import nl.knaw.dans.bagit.hash.SupportedAlgorithm;
import nl.knaw.dans.bagit.reader.BagReader;

public class BagVerifierTest extends TempFolderTest{
  static {
    if (Security.getProvider("BC") == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }
  
  private Path rootDir = Paths.get(new File("src/test/resources/bags/v0_97/bag").toURI());
  
  private BagVerifier sut = new BagVerifier();
  private BagReader reader = new BagReader();
  
  @Test
  public void testValidWhenHiddenFolderNotIncluded() throws Exception{
	  Path copyDir = copyBagToTempFolder(rootDir);
	  Files.createDirectory(copyDir.resolve("data").resolve(".someHiddenFolder"));
	  TestUtils.makeFilesHiddenOnWindows(copyDir);
	  
	  Bag bag = reader.read(copyDir);
	  sut.isValid(bag, true);
  }
  
  @Test
  public void testValidWithHiddenFile() throws Exception{
	  Path copyDir = copyBagToTempFolder(rootDir);
	  Files.createFile(copyDir.resolve("data").resolve(".someHiddenFile"));
	  TestUtils.makeFilesHiddenOnWindows(copyDir);
	  
	  Bag bag = reader.read(copyDir);
	  sut.isValid(bag, true);
  }
  
  @Test
  public void testInvalidWithHiddenFile() throws Exception{
	  Path copyDir = copyBagToTempFolder(rootDir);
	  Files.createFile(copyDir.resolve("data").resolve(".someHiddenFile"));
	  TestUtils.makeFilesHiddenOnWindows(copyDir);
	  
	  Bag bag = reader.read(copyDir);
	  Assertions.assertThrows(FileNotInManifestException.class, () -> { sut.isValid(bag, false); });
  }
  
  @Test
  public void testStandardSupportedAlgorithms() throws Exception{
    List<String> algorithms = Arrays.asList("md5", "sha1", "sha256", "sha512");
    for(String alg : algorithms){
      StandardSupportedAlgorithms algorithm = StandardSupportedAlgorithms.valueOf(alg.toUpperCase());
      Manifest manifest = new Manifest(algorithm);
      sut.checkHashes(manifest);
    }
  }
  
  @Test
  public void testMD5Bag() throws Exception{
	  Path bagDir = Paths.get("src", "test", "resources", "md5Bag");
	  Bag bag = reader.read(bagDir);
	  sut.isValid(bag, true);
  }
  
  @Test
  public void testSHA1Bag() throws Exception{
	  Path bagDir = Paths.get("src", "test", "resources", "sha1Bag");
	  Bag bag = reader.read(bagDir);
	  sut.isValid(bag, true);
  }
  
  @Test
  public void testSHA224Bag() throws Exception{
	  Path bagDir = Paths.get("src", "test", "resources", "sha224Bag");
	  Bag bag = reader.read(bagDir);
	  sut.isValid(bag, true);
  }
  
  @Test
  public void testSHA256Bag() throws Exception{
	  Path bagDir = Paths.get("src", "test", "resources", "sha256Bag");
	  Bag bag = reader.read(bagDir);
	  sut.isValid(bag, true);
  }
  
  @Test
  public void testSHA512Bag() throws Exception{
	  Path bagDir = Paths.get("src", "test", "resources", "sha512Bag");
	  Bag bag = reader.read(bagDir);
	  sut.isValid(bag, true);
  }
  
  @Test
  public void testVersion0_97IsValid() throws Exception{
    Bag bag = reader.read(rootDir);
    
    sut.isValid(bag, true);
  }
  
  @Test
  public void testVersion2_0IsValid() throws Exception{
    rootDir = Paths.get(new File("src/test/resources/bags/v2_0/bag").toURI());
    Bag bag = reader.read(rootDir);
    
    sut.isValid(bag, true);
  }
  
  @Test
  public void testIsComplete() throws Exception{
    Bag bag = reader.read(rootDir);
    
    sut.isComplete(bag, true);
  }
  
  @Test
  public void testCorruptPayloadFile() throws Exception{
    rootDir = Paths.get(new File("src/test/resources/corruptPayloadFile").toURI());
    Bag bag = reader.read(rootDir);
    
    Assertions.assertThrows(CorruptChecksumException.class, () -> { sut.isValid(bag, true); });
  }
  
  @Test
  public void testCorruptTagFile() throws Exception{
    rootDir = Paths.get(new File("src/test/resources/corruptTagFile").toURI());
    Bag bag = reader.read(rootDir);
    
    Assertions.assertThrows(CorruptChecksumException.class, () -> { sut.isValid(bag, true); });
  }
  
  @Test
  public void testErrorWhenUnspportedAlgorithmException() throws Exception{
    Path sha3BagDir = Paths.get(getClass().getClassLoader().getResource("sha3Bag").toURI());
    MySupportedNameToAlgorithmMapping mapping = new MySupportedNameToAlgorithmMapping();
    BagReader extendedReader = new BagReader(mapping);
    Bag bag = extendedReader.read(sha3BagDir);
    
    Assertions.assertThrows(UnsupportedAlgorithmException.class, () -> { sut.isValid(bag, true); });
  }
  
  @Test
  public void testVerificationExceptionIsThrownForNoSuchAlgorithmException() throws Exception{
    Path unreadableFile = createFile("newFile");
    
    Manifest manifest = new Manifest(new SupportedAlgorithm() {
      @Override
      public String getMessageDigestName() {
        return "FOO";
      }
      @Override
      public String getBagitName() {
        return "foo";
      }
    });
    manifest.getFileToChecksumMap().put(unreadableFile, "foo");
    
    Assertions.assertThrows(VerificationException.class, () -> { sut.checkHashes(manifest); });
  }
  
  @Test
  public void testAddSHA3SupportViaExtension() throws Exception{
    Path sha3BagDir = Paths.get(new File("src/test/resources/sha3Bag").toURI());
    MySupportedNameToAlgorithmMapping mapping = new MySupportedNameToAlgorithmMapping();
    BagReader extendedReader = new BagReader(mapping);
    Bag bag = extendedReader.read(sha3BagDir);
    try(BagVerifier extendedSut = new BagVerifier(mapping)){
      extendedSut.isValid(bag, true);
    }
  }
  
  /*
   * Technically valid but highly discouraged
   */
  @Test
  public void testManifestsWithLeadingDotSlash() throws Exception{
    Path bagPath = Paths.get(new File("src/test/resources/bag-with-leading-dot-slash-in-manifest").toURI());
    Bag bag = reader.read(bagPath);
    
    sut.isValid(bag, true);
  }
  
  @Test
  public void testCanQuickVerify() throws Exception{
    Bag bag = reader.read(rootDir);
    boolean canQuickVerify = BagVerifier.canQuickVerify(bag);
    Assertions.assertFalse(canQuickVerify,
        "Since " + bag.getRootDir() + " DOES NOT contain the metadata Payload-Oxum then it should return false!");
    
    Path passingRootDir = Paths.get(new File("src/test/resources/bags/v0_94/bag").toURI());
    bag = reader.read(passingRootDir);
    canQuickVerify = BagVerifier.canQuickVerify(bag);
    Assertions.assertTrue(canQuickVerify,
        "Since " + bag.getRootDir() + " DOES contain the metadata Payload-Oxum then it should return true!");
  }
  
  @Test 
  public void testQuickVerify() throws Exception{
    Path passingRootDir = Paths.get(new File("src/test/resources/bags/v0_94/bag").toURI());
    Bag bag = reader.read(passingRootDir);
    
    BagVerifier.quicklyVerify(bag);
  }
}
