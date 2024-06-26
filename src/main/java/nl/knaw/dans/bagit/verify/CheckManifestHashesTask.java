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
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Collection;
import java.util.Map.Entry;
import java.util.ResourceBundle;
import java.util.concurrent.CountDownLatch;

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
  
  public CheckManifestHashesTask(final Entry<Path, String> entry, final String algorithm, final CountDownLatch latch, final Collection<Exception> exceptions) {
    this.entry = entry;
    this.algorithm = algorithm;
    this.latch = latch;
    this.exceptions = exceptions;
  }

  @Override
  public void run() {
    try {
      final MessageDigest messageDigest = MessageDigest.getInstance(algorithm);
      checkManifestEntry(entry, messageDigest, algorithm);
    } catch (IOException | CorruptChecksumException | NoSuchAlgorithmException e) {
      exceptions.add(e);
    }
    latch.countDown();
  }
  
  protected static void checkManifestEntry(final Entry<Path, String> entry, final MessageDigest messageDigest, final String algorithm) throws IOException, CorruptChecksumException{
    if(Files.exists(entry.getKey())){
      logger.debug(messages.getString("checking_checksums"), entry.getKey(), entry.getValue());
      final String hash = Hasher.hash(entry.getKey(), messageDigest);
      logger.debug("computed hash [{}] for file [{}]", hash, entry.getKey());
      if(!hash.equals(entry.getValue())){
        throw new CorruptChecksumException(messages.getString("corrupt_checksum_error"), entry.getKey(), algorithm, entry.getValue(), hash);
      }
    }
    //if the file doesn't exist it will be caught by checkAllFilesListedInManifestExist method
  }
}
