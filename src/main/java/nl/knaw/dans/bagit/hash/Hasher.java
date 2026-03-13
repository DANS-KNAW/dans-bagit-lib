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

import nl.knaw.dans.bagit.domain.FetchItem;
import nl.knaw.dans.bagit.domain.Manifest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
import java.util.Collection;
import java.util.Collections;
import java.util.Formatter;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.ResourceBundle;

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

    private static final long DEFAULT_CHUNK_SIZE = 1024L * 1024L * 1024L; // 1 GiB
    private static final int DEFAULT_MAX_RETRIES = 5;
    private static final int DEFAULT_RETRY_SLEEP_MS = 5000;

    private Hasher() {
        //intentionally left empty
    }

    /**
     * Create a HEX formatted string checksum hash of the file
     *
     * @param path          the {@link Path} (file) to hash
     * @param messageDigest the {@link MessageDigest} object representing the hashing algorithm
     * @return the hash as a hex formated string
     * @throws IOException if there is a problem reading the file
     */
    public static String hash(final Path path, final MessageDigest messageDigest) throws IOException {
        updateMessageDigests(path, Collections.singletonList(messageDigest));

        return formatMessageDigest(messageDigest);
    }

    /**
     * Create a HEX formatted string checksum hash of the data from the URL
     *
     * @param url           the {@link URL} to hash
     * @param messageDigest the {@link MessageDigest} object representing the hashing algorithm
     * @return the hash as a hex-formatted string
     * @throws IOException if there is a problem reading from the URL
     */
    public static String hash(final URL url, final MessageDigest messageDigest) throws IOException {
        return hash(url, messageDigest, null);
    }

    /**
     * Create a HEX formatted string checksum hash of the data from the {@link FetchItem}
     *
     * @param item          the {@link FetchItem} to hash
     * @param messageDigest the {@link MessageDigest} object representing the hashing algorithm
     * @param extraHeaders  optional extra headers to send with the request
     * @return the hash as a hex formatted string
     * @throws IOException if there is a problem reading from the URL
     */
    public static String hash(final FetchItem item, final MessageDigest messageDigest, final Map<String, String> extraHeaders) throws IOException {
        long totalSize = (item.length != null && item.length >= 0) ? item.length : -1;
        URL currentUrl = item.url;
        Map<String, String> currentHeaders = extraHeaders;

        if (!currentUrl.getProtocol().startsWith("http")) {
            return hashFullStream(currentUrl, messageDigest, currentHeaders);
        }

        long chunkSize = Long.getLong(CHUNK_SIZE_PROP, DEFAULT_CHUNK_SIZE);
        int maxRetries = Integer.getInteger(MAX_RETRIES_PROP, DEFAULT_MAX_RETRIES);
        int retrySleepMs = Integer.getInteger(RETRY_SLEEP_MS_PROP, DEFAULT_RETRY_SLEEP_MS);

        long offset = 0;
        while (totalSize < 0 || offset < totalSize) {
            long end = (totalSize > 0) ? Math.min(offset + chunkSize - 1, totalSize - 1) : offset + chunkSize - 1;
            String range = "bytes=" + offset + "-" + end;

            final URL finalUrl = currentUrl;
            final Map<String, String> finalHeaders = currentHeaders;
            final long finalTotalSize = totalSize;

            try {
                ChunkResult result = executeWithRetry(() -> {
                    HttpURLConnection conn = openRangedConnection(finalUrl, range, finalHeaders);
                    int code = conn.getResponseCode();

                    // Manual redirect following
                    if (code >= 300 && code < 400) {
                        return ChunkResult.redirect(conn.getHeaderField("Location"));
                    }

                    if (code == 206) {
                        return handlePartialContent(conn, messageDigest, finalTotalSize);
                    }
                    else if (code == 200) {
                        logger.info("Server returned 200 OK for range request (probably range requests are not supported); downloading full stream from {}", finalUrl);
                        try (InputStream is = conn.getInputStream()) {
                            updateDigestFromStream(is, messageDigest);
                        }
                        return ChunkResult.fullStream(formatMessageDigest(messageDigest));
                    }
                    else {
                        throw new IOException("Unexpected response code " + code + " for " + finalUrl);
                    }
                }, "Error fetching range " + range + " from " + currentUrl, maxRetries, retrySleepMs);

                logger.debug("Processing chunk result for range {} from {}", range, currentUrl);

                if (result.type == ChunkResultType.FULL_STREAM_SUCCESS) {
                    logger.debug("Successfully processed full stream for range {} from {}", range, currentUrl);
                    return result.hash;
                }
                else if (result.type == ChunkResultType.REDIRECT) {
                    URL nextUrl = new URL(currentUrl, result.location);
                    if (!currentUrl.getAuthority().equals(nextUrl.getAuthority()) || !currentUrl.getProtocol().equals(nextUrl.getProtocol())) {
                        currentHeaders = null;
                    }
                    currentUrl = nextUrl;
                    logger.debug("Redirected to {}, currentHeaders stripped: {}", currentUrl, (currentHeaders == null));
                    // Skip offset update and retry the current chunk with new URL
                }
                else if (result.type == ChunkResultType.SUCCESS) {
                    offset += result.bytesRead;
                    if (totalSize < 0 && result.totalSize > 0) {
                        totalSize = result.totalSize;
                    }
                    logger.debug("Successfully processed chunk for range {} from {}", range, currentUrl);
                    logger.debug("Read {} of {}{}", offset, totalSize > 0 ? totalSize : "Unknown", totalSize > 0 ? " (" + (offset * 100L / totalSize) + "%)" : "");
                }
            }
            catch (IOException e) {
                logger.info("Falling back to full stream for {} after failed range requests", currentUrl);
                messageDigest.reset();
                return hashFullStream(currentUrl, messageDigest, currentHeaders);
            }
        }

        return formatMessageDigest(messageDigest);
    }

    private static String hashFullStream(final URL url, final MessageDigest messageDigest, final Map<String, String> extraHeaders) throws IOException {
        URL currentUrl = url;
        Map<String, String> currentHeaders = extraHeaders;

        while (true) {
            URLConnection conn = currentUrl.openConnection();
            if (conn instanceof HttpURLConnection httpConn) {
                httpConn.setInstanceFollowRedirects(false);
                if (currentHeaders != null) {
                    for (Entry<String, String> entry : currentHeaders.entrySet()) {
                        httpConn.setRequestProperty(entry.getKey(), entry.getValue());
                    }
                }
                int code = httpConn.getResponseCode();
                if (code >= 300 && code < 400) {
                    String location = httpConn.getHeaderField("Location");
                    URL nextUrl = new URL(currentUrl, location);
                    if (!currentUrl.getAuthority().equals(nextUrl.getAuthority()) || !currentUrl.getProtocol().equals(nextUrl.getProtocol())) {
                        currentHeaders = null;
                    }
                    currentUrl = nextUrl;
                    continue;
                }
                if (code != 200) {
                    throw new IOException("Unexpected response code " + code + " for " + currentUrl);
                }
            }
            try (final InputStream is = conn.getInputStream()) {
                updateDigestFromStream(is, messageDigest);
            }
            break;
        }
        return formatMessageDigest(messageDigest);
    }

    /**
     * Create a HEX formatted string checksum hash of the data from the URL
     *
     * @param url           the {@link URL} to hash
     * @param messageDigest the {@link MessageDigest} object representing the hashing algorithm
     * @param extraHeaders  optional extra headers to send with the request
     * @return the hash as a hex formatted string
     * @throws IOException if there is a problem reading from the URL
     */
    public static String hash(final URL url, final MessageDigest messageDigest, final Map<String, String> extraHeaders) throws IOException {
        return hash(new FetchItem(url, -1L, null), messageDigest, extraHeaders);
    }

    private static ChunkResult handlePartialContent(HttpURLConnection conn, MessageDigest messageDigest, long currentTotalSize) throws IOException {
        long totalSize = currentTotalSize;
        if (totalSize < 0) {
            String contentRange = conn.getHeaderField("Content-Range");
            if (contentRange != null && contentRange.contains("/")) {
                try {
                    totalSize = Long.parseLong(contentRange.substring(contentRange.lastIndexOf("/") + 1));
                }
                catch (NumberFormatException e) {
                    logger.warn("Could not parse Content-Range: {}", contentRange);
                }
            }
        }
        try (InputStream is = conn.getInputStream()) {
            int bytesRead = updateDigestFromStream(is, messageDigest);
            if (bytesRead < 0) {
                throw new IOException("Stream closed unexpectedly for " + conn.getURL());
            }
            return ChunkResult.success(bytesRead, totalSize);
        }
    }

    private static ChunkResult executeWithRetry(RetryableOperation<ChunkResult> operation, String description, int maxRetries, int retrySleepMs) throws IOException {
        for (int attempt = 0; attempt < maxRetries; attempt++) {
            try {
                ChunkResult result = operation.execute();
                if (result.type == ChunkResultType.REDIRECT) {
                    return result; // Break the retry loop for redirects
                }
                return result;
            }
            catch (IOException e) {
                logger.warn("{} (attempt {}/{}): {}", description, attempt + 1, maxRetries, e.getMessage());
                if (attempt < maxRetries - 1) {
                    try {
                        Thread.sleep(retrySleepMs);
                    }
                    catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        throw new IOException("Interrupted during retry sleep", ie);
                    }
                }
                else {
                    throw e;
                }
            }
        }
        throw new IOException("Max retries exceeded");
    }

    @FunctionalInterface
    private interface RetryableOperation<T> {
        T execute() throws IOException;
    }

    private enum ChunkResultType {
        SUCCESS, REDIRECT, FULL_STREAM_SUCCESS
    }

    /**
     * Represents the result of a chunk operation when processing data for hashing. A chunk operation can have various results, such as a successful read, a redirection to another location, or
     * successful processing of a complete stream.
     */
    private static class ChunkResult {
        final ChunkResultType type;
        final int bytesRead;
        final long totalSize;
        final String location;
        final String hash;

        private ChunkResult(ChunkResultType type, int bytesRead, long totalSize, String location, String hash) {
            this.type = type;
            this.bytesRead = bytesRead;
            this.totalSize = totalSize;
            this.location = location;
            this.hash = hash;
        }

        static ChunkResult success(int bytesRead, long totalSize) {
            return new ChunkResult(ChunkResultType.SUCCESS, bytesRead, totalSize, null, null);
        }

        static ChunkResult redirect(String location) {
            return new ChunkResult(ChunkResultType.REDIRECT, 0, -1, location, null);
        }

        static ChunkResult fullStream(String hash) {
            return new ChunkResult(ChunkResultType.FULL_STREAM_SUCCESS, 0, -1, null, hash);
        }
    }

    /**
     * Opens a HttpURLConnection for the given range.
     */
    private static HttpURLConnection openRangedConnection(URL url, String range, final Map<String, String> extraHeaders) throws IOException {
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        if (extraHeaders != null) {
            for (Entry<String, String> entry : extraHeaders.entrySet()) {
                conn.setRequestProperty(entry.getKey(), entry.getValue());
            }
        }
        conn.setInstanceFollowRedirects(false);
        if (range != null) {
            conn.setRequestProperty("Range", range);
        }
        return conn;
    }

    /**
     * Reads from the InputStream and updates the MessageDigest. Returns the number of bytes read.
     */
    private static int updateDigestFromStream(InputStream is, MessageDigest messageDigest) throws IOException {
        byte[] buffer = new byte[CHUNK_SIZE];
        int totalRead = 0;
        int read = is.read(buffer);
        while (read != -1) {
            messageDigest.update(buffer, 0, read);
            totalRead += read;
            read = is.read(buffer);
        }
        return totalRead;
    }

    /**
     * Update the Manifests with the file's hash
     *
     * @param path                       the {@link Path} (file) to hash
     * @param manifestToMessageDigestMap the map between {@link Manifest} and {@link MessageDigest}
     * @throws IOException if there is a problem reading the file
     */
    public static void hash(final Path path, final Map<Manifest, MessageDigest> manifestToMessageDigestMap) throws IOException {
        updateMessageDigests(path, manifestToMessageDigestMap.values());
        addMessageDigestHashToManifest(path, manifestToMessageDigestMap);
    }

    static void updateMessageDigests(final Path path, final Collection<MessageDigest> messageDigests) throws IOException {
        try (final InputStream is = new BufferedInputStream(Files.newInputStream(path, StandardOpenOption.READ))) {
            final byte[] buffer = new byte[CHUNK_SIZE];
            int read = is.read(buffer);

            while (read != -1) {
                for (final MessageDigest messageDigest : messageDigests) {
                    messageDigest.update(buffer, 0, read);
                }
                read = is.read(buffer);
            }
        }
    }

    private static void addMessageDigestHashToManifest(final Path path, final Map<Manifest, MessageDigest> manifestToMessageDigestMap) {
        for (final Entry<Manifest, MessageDigest> entry : manifestToMessageDigestMap.entrySet()) {
            final String hash = formatMessageDigest(entry.getValue());
            logger.debug(messages.getString("adding_checksum"), path, hash);
            entry.getKey().getFileToChecksumMap().put(path, hash);
        }
    }

    //Convert the byte to hex format
    private static String formatMessageDigest(final MessageDigest messageDigest) {
        try (final Formatter formatter = new Formatter()) {
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
    public static Map<Manifest, MessageDigest> createManifestToMessageDigestMap(final Collection<SupportedAlgorithm> algorithms) throws NoSuchAlgorithmException {
        final Map<Manifest, MessageDigest> map = new HashMap<>();

        for (final SupportedAlgorithm algorithm : algorithms) {
            final MessageDigest messageDigest = MessageDigest.getInstance(algorithm.getMessageDigestName());
            final Manifest manifest = new Manifest(algorithm);
            map.put(manifest, messageDigest);
        }

        return map;
    }
}
