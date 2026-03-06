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
package nl.knaw.dans.bagit.writer;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import nl.knaw.dans.bagit.PrivateConstructorTest;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import nl.knaw.dans.bagit.domain.Metadata;
import nl.knaw.dans.bagit.domain.Version;
import nl.knaw.dans.bagit.reader.KeyValueReader;
import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.List;

public class MetadataWriterTest extends PrivateConstructorTest {
  
  @Test
  public void testClassIsWellDefined() throws NoSuchMethodException, InvocationTargetException, InstantiationException, IllegalAccessException{
    assertUtilityClassWellDefined(MetadataWriter.class);
  }
  
  @Test
  public void testWriteBagitInfoFile() throws IOException{
    Path rootDir = createDirectory("writeBagitInfo");
    Path bagInfo = rootDir.resolve("bag-info.txt");
    Path packageInfo = rootDir.resolve("package-info.txt");
    Metadata metadata = new Metadata();
    metadata.add("key1", "value1");
    metadata.add("key2", "value2");
    metadata.add("key3", "value3");
    
    Assertions.assertFalse(Files.exists(bagInfo));
    Assertions.assertFalse(Files.exists(packageInfo));
    
    MetadataWriter.writeBagMetadata(metadata, new Version(0,96), rootDir, StandardCharsets.UTF_8);
    Assertions.assertTrue(Files.exists(bagInfo));
    
    MetadataWriter.writeBagMetadata(metadata, new Version(0,95), rootDir, StandardCharsets.UTF_8);
    Assertions.assertTrue(Files.exists(packageInfo));
  }

  @Test
  public void testWriteAndReadMultilineMetadata() throws Exception {
    Path rootDir = createDirectory("multilineTest");
    Metadata metadata = new Metadata();
    String multilineValue = "This is a" + System.lineSeparator() + "multi-line" + System.lineSeparator() + "value.";
    metadata.add("Description", multilineValue);
    metadata.add("Contact-Name", "John Doe");

    MetadataWriter.writeBagMetadata(metadata, new Version(1, 0), rootDir, StandardCharsets.UTF_8);

    Path bagInfo = rootDir.resolve("bag-info.txt");
    String content = Files.readString(bagInfo, StandardCharsets.UTF_8);

    // Check if subsequent lines are indented
    String[] lines = content.split("\\R");
    Assertions.assertTrue(lines[0].startsWith("Description: "));
    Assertions.assertTrue(lines[1].startsWith(" "), "Line 2 should be indented");
    Assertions.assertTrue(lines[2].startsWith(" "), "Line 3 should be indented");

    // Read it back
    List<SimpleImmutableEntry<String, String>> readMetadata = KeyValueReader.readKeyValuesFromFile(bagInfo, ":", StandardCharsets.UTF_8);
    
    boolean foundDescription = false;
    for (SimpleImmutableEntry<String, String> entry : readMetadata) {
      if ("Description".equals(entry.getKey())) {
        Assertions.assertEquals(multilineValue, entry.getValue());
        foundDescription = true;
      }
    }
    Assertions.assertTrue(foundDescription);
  }

  @Test
  public void testSanitizeMetadata() throws Exception {
    Path rootDir = createDirectory("sanitizeTest");
    Metadata metadata = new Metadata();
    // \u0000 is a non-printable char, \u0007 is bell
    String dirtyValue = "Value with\u0000 non-printable\u0007 chars.";
    String cleanValue = "Value with non-printable chars.";
    metadata.add("Custom-Key", dirtyValue);

    MetadataWriter.writeBagMetadata(metadata, new Version(1, 0), rootDir, StandardCharsets.UTF_8);

    Path bagInfo = rootDir.resolve("bag-info.txt");
    List<SimpleImmutableEntry<String, String>> readMetadata = KeyValueReader.readKeyValuesFromFile(bagInfo, ":", StandardCharsets.UTF_8);
    
    for (SimpleImmutableEntry<String, String> entry : readMetadata) {
      if ("Custom-Key".equals(entry.getKey())) {
        Assertions.assertEquals(cleanValue, entry.getValue());
      }
    }
  }

  @Test
  public void testWrapLongLines() throws Exception {
    Path rootDir = createDirectory("wrapLongLinesTest");
    Metadata metadata = new Metadata();
    String longValue = "This is a very long value that should definitely exceed the seventy-nine characters limit that is recommended by the BagIt RFC 8493 section two point two point two.";
    // Length is ~166 chars.
    metadata.add("Long-Key", longValue);

    MetadataWriter.writeBagMetadata(metadata, new Version(1, 0), rootDir, StandardCharsets.UTF_8);

    Path bagInfo = rootDir.resolve("bag-info.txt");
    String content = Files.readString(bagInfo, StandardCharsets.UTF_8);

    String[] lines = content.split("\\R");
    for (String line : lines) {
      Assertions.assertTrue(line.length() <= 80, "Line length should be <= 80 (79 chars + potential newline): " + line.length());
      if (!line.startsWith("Long-Key: ")) {
        Assertions.assertTrue(line.startsWith(" "), "Wrapped lines should be indented");
      }
    }

    // Read it back
    List<SimpleImmutableEntry<String, String>> readMetadata = KeyValueReader.readKeyValuesFromFile(bagInfo, ":", StandardCharsets.UTF_8);
    boolean foundLongKey = false;
    for (SimpleImmutableEntry<String, String> entry : readMetadata) {
      if ("Long-Key".equals(entry.getKey())) {
        String expectedValue = longValue.replace(" ", System.lineSeparator());
        // Since it's wrapped at spaces, the space is replaced by newline in reading if it's joined by newline
        // But wrapLine also preserves spaces? Let's check what it actually produces.
        // It should match the longValue with some spaces replaced by newlines.
        Assertions.assertEquals(longValue, entry.getValue().replace(System.lineSeparator(), " "));
        foundLongKey = true;
      }
    }
    Assertions.assertTrue(foundLongKey);
  }

  @Test
  public void testMultilineAndWrapping() throws Exception {
    Path rootDir = createDirectory("multilineAndWrappingTest");
    Metadata metadata = new Metadata();
    // A multiline value where the first line is short and the second is long
    String value = "Short first line\nThis is a very long second line that will definitely need wrapping because it's much longer than seventy-nine characters.";
    metadata.add("Description", value);

    MetadataWriter.writeBagMetadata(metadata, new Version(1, 0), rootDir, java.nio.charset.StandardCharsets.UTF_8);

    Path bagInfo = rootDir.resolve("bag-info.txt");
    String content = Files.readString(bagInfo, java.nio.charset.StandardCharsets.UTF_8);

    // Check for double newlines or lines containing only a space
    String[] lines = content.split("\\r?\\n");
    for (int i = 0; i < lines.length; i++) {
      String line = lines[i];
      Assertions.assertFalse(line.isEmpty() && i < lines.length - 1, "Should not have empty lines in the middle (caused by double newlines)");
      if (i > 0) {
        // All lines after the first one of an entry must be indented
        Assertions.assertTrue(line.startsWith(" "), "Continuation line must start with a space: [" + line + "]");
        // If it was a double newline, we'd see a line that is just " " followed by another line
        Assertions.assertNotEquals(" ", line, "Should not have a line that is just a single space");
      }
    }
  }
}
