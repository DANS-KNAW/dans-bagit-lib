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

import java.io.IOException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Collection;
import java.util.Map;
import java.util.Map.Entry;
import java.util.ResourceBundle;
import java.util.concurrent.CountDownLatch;

import nl.knaw.dans.bagit.domain.FetchItem;
import nl.knaw.dans.bagit.exceptions.CorruptChecksumException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import nl.knaw.dans.bagit.hash.Hasher;

/**
 * Checks a give file to make sure the given checksum hash matches the computed checksum hash.
 * This is thread safe so you can call many at a time.
 */
@SuppressWarnings("PMD.DoNotUseThreads")
public class CheckManifestHashesTask implements Runnable {
  private static final Logger logger = LoggerFactory.getLogger(CheckManifestHashesTask.class);
  private static final ResourceBundle messages = ResourceBundle.getBundle("MessageBundle");
  
  private transient final Entry<Path, String> entry;
  private transient final CountDownLatch latch;
  private transient final Collection<Exception> exceptions;
  private transient final String algorithm;
  private transient final Map<Path, FetchItem> fetchItems;
  private transient final boolean holey;
  private transient final Map<String, String> extraHeaders;
  private transient final Map<String, Map<String, String>> urlConfigs;

  public CheckManifestHashesTask(final Entry<Path, String> entry, final String algorithm, final CountDownLatch latch, final Collection<Exception> exceptions) {
    this(entry, algorithm, latch, exceptions, null, false, null, null);
  }

  public CheckManifestHashesTask(final Entry<Path, String> entry, final String algorithm, final CountDownLatch latch, final Collection<Exception> exceptions, final Map<Path, FetchItem> fetchItems, final boolean holey) {
    this(entry, algorithm, latch, exceptions, fetchItems, holey, null, null);
  }

  public CheckManifestHashesTask(final Entry<Path, String> entry, final String algorithm, final CountDownLatch latch, final Collection<Exception> exceptions, final Map<Path, FetchItem> fetchItems, final boolean holey, final Map<String, String> extraHeaders) {
    this(entry, algorithm, latch, exceptions, fetchItems, holey, extraHeaders, null);
  }

  public CheckManifestHashesTask(final Entry<Path, String> entry, final String algorithm, final CountDownLatch latch, final Collection<Exception> exceptions, final Map<Path, FetchItem> fetchItems, final boolean holey, final Map<String, String> extraHeaders, final Map<String, Map<String, String>> urlConfigs) {
    this.entry = entry;
    this.algorithm = algorithm;
    this.latch = latch;
    this.exceptions = exceptions;
    this.fetchItems = fetchItems;
    this.holey = holey;
    this.extraHeaders = extraHeaders;
    this.urlConfigs = urlConfigs;
  }

  @Override
  public void run() {
    try {
      final MessageDigest messageDigest = MessageDigest.getInstance(algorithm);
      checkManifestEntry(entry, messageDigest, algorithm, fetchItems, holey, extraHeaders, urlConfigs);
    } catch (IOException | CorruptChecksumException | NoSuchAlgorithmException e) {
      exceptions.add(e);
    }
    latch.countDown();
  }

  protected static void checkManifestEntry(final Entry<Path, String> entry, final MessageDigest messageDigest, final String algorithm) throws IOException, CorruptChecksumException {
    checkManifestEntry(entry, messageDigest, algorithm, null, false, null, null);
  }

  protected static void checkManifestEntry(final Entry<Path, String> entry, final MessageDigest messageDigest, final String algorithm, final Map<Path, FetchItem> fetchItems, final boolean allowHoley) throws IOException, CorruptChecksumException {
    checkManifestEntry(entry, messageDigest, algorithm, fetchItems, allowHoley, null, null);
  }

  protected static void checkManifestEntry(final Entry<Path, String> entry, final MessageDigest messageDigest, final String algorithm, final Map<Path, FetchItem> fetchItems, final boolean allowHoley, final Map<String, String> extraHeaders) throws IOException, CorruptChecksumException {
    checkManifestEntry(entry, messageDigest, algorithm, fetchItems, allowHoley, extraHeaders, null);
  }

  protected static void checkManifestEntry(final Entry<Path, String> entry, final MessageDigest messageDigest, final String algorithm, final Map<Path, FetchItem> fetchItems, final boolean allowHoley, final Map<String, String> extraHeaders, final Map<String, Map<String, String>> urlConfigs) throws IOException, CorruptChecksumException {
    if (Files.exists(entry.getKey())) {
      logger.debug(messages.getString("checking_checksums"), entry.getKey(), entry.getValue());
      final String hash = Hasher.hash(entry.getKey(), messageDigest);
      logger.debug("computed hash [{}] for file [{}]", hash, entry.getKey());
      if (!hash.equals(entry.getValue())) {
        throw new CorruptChecksumException(messages.getString("corrupt_checksum_error"), entry.getKey(), algorithm, entry.getValue(), hash);
      }
    } else if (allowHoley && fetchItems != null && fetchItems.containsKey(entry.getKey())) {
      final FetchItem item = fetchItems.get(entry.getKey());
      logger.debug("File {} does not exist, but it is in fetch.txt, and allowHoley is true. Hashing from URL: {}", entry.getKey(), item.url);
      final Map<String, String> mergedHeaders = mergeHeaders(item.url, extraHeaders, urlConfigs);
      final String hash = Hasher.hash(item, messageDigest, mergedHeaders);
      logger.debug("computed hash [{}] for url [{}]", hash, item.url);
      if (!hash.equals(entry.getValue())) {
        throw new CorruptChecksumException(messages.getString("corrupt_checksum_error"), entry.getKey(), algorithm, entry.getValue(), hash);
      }
    }
    //if the file doesn't exist it will be caught by checkAllFilesListedInManifestExist method
  }

  private static Map<String, String> mergeHeaders(final URL url, final Map<String, String> extraHeaders, final Map<String, Map<String, String>> urlConfigs) {
    if (urlConfigs == null || urlConfigs.isEmpty()) {
      return extraHeaders;
    }

    final Map<String, String> mergedHeaders = new java.util.HashMap<>();
    if (extraHeaders != null) {
      mergedHeaders.putAll(extraHeaders);
    }

    final String urlString = url.toString();
    for (final Entry<String, Map<String, String>> configEntry : urlConfigs.entrySet()) {
      if (urlString.startsWith(configEntry.getKey())) {
        mergedHeaders.putAll(configEntry.getValue());
      }
    }

    return mergedHeaders;
  }
}
