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
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ResourceBundle;
import java.util.AbstractMap.SimpleImmutableEntry;

import nl.knaw.dans.bagit.domain.Metadata;
import nl.knaw.dans.bagit.domain.Version;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Responsible for writing out the bag {@link Metadata} to the filesystem
 */
public final class MetadataWriter {
  private static final Logger logger = LoggerFactory.getLogger(MetadataWriter.class);
  private static final Version VERSION_0_95 = new Version(0, 95);
  private static final ResourceBundle messages = ResourceBundle.getBundle("MessageBundle");

  private MetadataWriter(){
    //intentionall left empty
  }
  
  /**
   * Write the bag-info.txt (or package-info.txt) file to the specified outputDir with specified encoding (charsetName)
   * 
   * @param metadata the key value pair info in the bag-info.txt file
   * @param version the version of the bag you are writing
   * @param outputDir the root of the bag
   * @param charsetName the name of the encoding for the file
   * 
   * @throws IOException if there was a problem writing a file
   */
  public static void writeBagMetadata(final Metadata metadata, final Version version, final Path outputDir, final Charset charsetName) throws IOException{
    Path bagInfoFilePath = outputDir.resolve("bag-info.txt");
    if(version.isSameOrOlder(VERSION_0_95)){
      bagInfoFilePath = outputDir.resolve("package-info.txt");
    }
    logger.debug(messages.getString("writing_metadata_to_path"), bagInfoFilePath.getFileName(), outputDir);

    Files.deleteIfExists(bagInfoFilePath);
    final StringBuilder lines = new StringBuilder();
    
    for(final SimpleImmutableEntry<String, String> entry : metadata.getAll()){
      final String key = entry.getKey();
      String value = entry.getValue();
      value = value.replaceAll("[^\\x09\\x20-\\x7E\\x0A\\x0D\\x80-\\uFFFF]", "");
      lines.append(formatLine(key, value, version)).append(System.lineSeparator());
    }
    
    logger.debug(messages.getString("writing_line_to_file"), lines.toString(), bagInfoFilePath);
    Files.write(bagInfoFilePath, lines.toString().getBytes(charsetName), 
        StandardOpenOption.APPEND, StandardOpenOption.CREATE);
  }

  private static String formatLine(final String key, final String value, final Version version) {
    if (version.isSameOrOlder(VERSION_0_95)) {
      final String fullLine = key + ": " + value;
      return fullLine.replaceAll("(\\r\\n|\\r|\\n)", "$1 ");
    }
    
    final StringBuilder sb = new StringBuilder();
    final int keyPrefixLength = key.length() + 2; // "Key: "
    sb.append(key).append(": ");
    final String[] parts = value.split("(\\r\\n|\\r|\\n)", -1);
    
    for (int i = 0; i < parts.length; i++) {
      String line = parts[i];
      if (i > 0) {
        sb.append(System.lineSeparator());
        line = " " + line;
      }
      
      final int maxLength = i == 0 ? 79 - keyPrefixLength : 78; // Continuation lines have " " prefix
      // Check if it's already "well-wrapped" or short
      if (line.length() > maxLength) {
        sb.append(wrapLine(line, i == 0, i > 0, keyPrefixLength));
      } else {
        sb.append(line);
      }
    }
    return sb.toString();
  }

  private static String wrapLine(final String line, final boolean isFirstLine, final boolean startsWithNewline, final int keyPrefixLength) {
    final StringBuilder sb = new StringBuilder();
    int start = 0;
    boolean firstWrap = true;
    
    while (start < line.length()) {
      int maxLength = 78; // Indented line starts with " ", so 78 more chars = 79
      if (firstWrap && isFirstLine) {
        maxLength = 79 - keyPrefixLength;
      }
      
      int end = Math.min(start + maxLength, line.length());
      
      if (end < line.length()) {
        int lastSpace = line.lastIndexOf(' ', end);
        if (lastSpace > start) {
          end = lastSpace;
        }
      }
      
      String sub = line.substring(start, end);
      if (start > 0 || (firstWrap && startsWithNewline)) {
        sb.append(System.lineSeparator());
        sb.append(" ");
      }
      sb.append(sub);
      
      start = end;
      while (start < line.length() && line.charAt(start) == ' ') {
        start++;
      }
      firstWrap = false;
    }
    
    return sb.toString();
  }
}
