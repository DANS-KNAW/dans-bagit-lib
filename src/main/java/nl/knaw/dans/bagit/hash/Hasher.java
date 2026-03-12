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
package nl.knaw.dans.bagit.hash;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Formatter;
import java.util.HashMap;
import java.util.Map;
import java.util.ResourceBundle;
import java.util.Map.Entry;

import nl.knaw.dans.bagit.domain.Manifest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Convenience class for generating a HEX formatted string of the checksum hash. 
 */
public final class Hasher {
  private static final Logger logger = LoggerFactory.getLogger(Hasher.class);
  private static final int _64_KB = 1024 * 64;
  private static final int CHUNK_SIZE = _64_KB;
  private static final ResourceBundle messages = ResourceBundle.getBundle("MessageBundle");

  private static final String CHUNK_SIZE_PROP = "nl.knaw.dans.bagit.hash.chunkSize";
  private static final String MAX_RETRIES_PROP = "nl.knaw.dans.bagit.hash.maxRetries";
  private static final String RETRY_SLEEP_MS_PROP = "nl.knaw.dans.bagit.hash.retrySleepMs";

  private static final long DEFAULT_CHUNK_SIZE = 1024L * 1024L; // 1 MiB
  private static final int DEFAULT_MAX_RETRIES = 5;
  private static final int DEFAULT_RETRY_SLEEP_MS = 5000;
  
  private Hasher(){
    //intentionally left empty
  }
  
  /**
   * Create a HEX formatted string checksum hash of the file
   * 
   * @param path the {@link Path} (file) to hash
   * @param messageDigest the {@link MessageDigest} object representing the hashing algorithm
   * @return the hash as a hex formated string
   * @throws IOException if there is a problem reading the file
   */
  public static String hash(final Path path, final MessageDigest messageDigest) throws IOException {
    updateMessageDigests(path, Arrays.asList(messageDigest));
    
    return formatMessageDigest(messageDigest);
  }

  /**
   * Create a HEX formatted string checksum hash of the data from the URL
   *
   * @param url the {@link URL} to hash
   * @param messageDigest the {@link MessageDigest} object representing the hashing algorithm
   * @return the hash as a hex formatted string
   * @throws IOException if there is a problem reading from the URL
   */
  public static String hash(final URL url, final MessageDigest messageDigest) throws IOException {
    long totalSize = -1;
    boolean rangeSupported = false;
    URLConnection connection = url.openConnection();

    if (connection instanceof HttpURLConnection httpConnection) {
      httpConnection.setRequestMethod("HEAD");

      totalSize = httpConnection.getContentLengthLong();
      String acceptRanges = httpConnection.getHeaderField("Accept-Ranges");
      rangeSupported = "bytes".equalsIgnoreCase(acceptRanges);
    }

    if (rangeSupported && totalSize > 0) {
      logger.info("Range requests supported for {}, downloading in chunks", url);
      hashWithRangeRequests(url, messageDigest, totalSize);
    } else {
      logger.info("Range requests NOT supported or size unknown for {}, downloading full stream", url);
      try (final InputStream is = new BufferedInputStream(url.openStream())) {
        final byte[] buffer = new byte[CHUNK_SIZE];
        int read = is.read(buffer);

        while (read != -1) {
          messageDigest.update(buffer, 0, read);
          read = is.read(buffer);
        }
      }
    }

    return formatMessageDigest(messageDigest);
  }

  private static void hashWithRangeRequests(final URL url, final MessageDigest messageDigest, final long totalSize) throws IOException {
    long chunkSize = Long.getLong(CHUNK_SIZE_PROP, DEFAULT_CHUNK_SIZE);
    int maxRetries = Integer.getInteger(MAX_RETRIES_PROP, DEFAULT_MAX_RETRIES);
    int retrySleepMs = Integer.getInteger(RETRY_SLEEP_MS_PROP, DEFAULT_RETRY_SLEEP_MS);

    long offset = 0;
    while (offset < totalSize) {
      long end = Math.min(offset + chunkSize - 1, totalSize - 1);
      String range = "bytes=" + offset + "-" + end;
      
      boolean success = false;
      for (int attempt = 0; attempt < maxRetries; attempt++) {
        try {
          HttpURLConnection conn = (HttpURLConnection) url.openConnection();
          conn.setRequestProperty("Range", range);
          int code = conn.getResponseCode();
          
          if (code != 206 && code != 200) {
             throw new IOException("Unexpected response code " + code + " for range " + range);
          }
          
          try (InputStream is = conn.getInputStream()) {
            byte[] buffer = new byte[CHUNK_SIZE];
            int read = is.read(buffer);
            while (read != -1) {
              messageDigest.update(buffer, 0, read);
              offset += read;
              read = is.read(buffer);
            }
          }
          success = true;
          break;
        } catch (IOException e) {
          logger.warn("Error fetching range {} (attempt {}/{}): {}", range, attempt + 1, maxRetries, e.getMessage());
          if (attempt < maxRetries - 1) {
            try {
              Thread.sleep(retrySleepMs);
            } catch (InterruptedException ie) {
              Thread.currentThread().interrupt();
              throw new IOException("Interrupted during retry sleep", ie);
            }
          } else {
            throw e;
          }
        }
      }
      if (!success) {
        throw new IOException("Failed to fetch range " + range + " after " + maxRetries + " attempts");
      }
    }
  }
  
  /**
   * Update the Manifests with the file's hash
   * 
   * @param path the {@link Path} (file) to hash
   * @param manifestToMessageDigestMap the map between {@link Manifest} and {@link MessageDigest}
   * @throws IOException if there is a problem reading the file
   */
  public static void hash(final Path path, final Map<Manifest, MessageDigest> manifestToMessageDigestMap) throws IOException {
    updateMessageDigests(path, manifestToMessageDigestMap.values());
    addMessageDigestHashToManifest(path, manifestToMessageDigestMap);
  }
  
  static void updateMessageDigests(final Path path, final Collection<MessageDigest> messageDigests) throws IOException{
    try(final InputStream is = new BufferedInputStream(Files.newInputStream(path, StandardOpenOption.READ))){
      final byte[] buffer = new byte[CHUNK_SIZE];
      int read = is.read(buffer);
      
      while(read != -1) {
        for(final MessageDigest messageDigest : messageDigests){
          messageDigest.update(buffer, 0, read);
        }
        read = is.read(buffer);
      }
    }
  }
  
  private static void addMessageDigestHashToManifest(final Path path, final Map<Manifest, MessageDigest> manifestToMessageDigestMap){
    for(final Entry<Manifest, MessageDigest> entry : manifestToMessageDigestMap.entrySet()){
      final String hash = formatMessageDigest(entry.getValue());
      logger.debug(messages.getString("adding_checksum"), path, hash);
      entry.getKey().getFileToChecksumMap().put(path, hash);
    }
  }
  
  //Convert the byte to hex format
  private static String formatMessageDigest(final MessageDigest messageDigest){
    try(final Formatter formatter = new Formatter()){
      for (final byte b : messageDigest.digest()) {
        formatter.format("%02x", b);
      }
      
      return formatter.toString();
    }
  }
  
  /**
   * create a mapping between {@link Manifest} and {@link MessageDigest} for each each supplied {@link SupportedAlgorithm} 
   * 
   * @param algorithms the {@link SupportedAlgorithm} that you which to map to {@link MessageDigest} 
   * @return mapping between {@link Manifest} and {@link MessageDigest}
   * @throws NoSuchAlgorithmException if {@link MessageDigest} doesn't support the algorithm
   */
  @SuppressWarnings("PMD.AvoidInstantiatingObjectsInLoops")
  public static Map<Manifest, MessageDigest> createManifestToMessageDigestMap(final Collection<SupportedAlgorithm> algorithms) throws NoSuchAlgorithmException{
    final Map<Manifest, MessageDigest> map = new HashMap<>();

    for(final SupportedAlgorithm algorithm : algorithms){
      final MessageDigest messageDigest = MessageDigest.getInstance(algorithm.getMessageDigestName());
      final Manifest manifest = new Manifest(algorithm);
      map.put(manifest, messageDigest);
    }
    
    return map;
  }
}
