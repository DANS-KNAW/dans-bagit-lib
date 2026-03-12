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

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.atomic.AtomicInteger;

public class HasherUrlTest {

    private HttpServer server;
    private static final String TEST_DATA = "This is some test data that should be hashed correctly even with retries and range requests.";
    private static final byte[] TEST_DATA_BYTES = TEST_DATA.getBytes(StandardCharsets.UTF_8);
    private AtomicInteger requestCount = new AtomicInteger(0);

    @BeforeEach
    public void setup() throws IOException {
        server = HttpServer.create(new InetSocketAddress(0), 0);
        server.createContext("/test", new HttpHandler() {
            @Override
            public void handle(HttpExchange exchange) throws IOException {
                requestCount.incrementAndGet();
                String range = exchange.getRequestHeaders().getFirst("Range");
                
                if (range == null) {
                    // Full request
                    exchange.getResponseHeaders().set("Accept-Ranges", "bytes");
                    exchange.getResponseHeaders().set("Content-Length", String.valueOf(TEST_DATA_BYTES.length));
                    exchange.sendResponseHeaders(200, TEST_DATA_BYTES.length);
                    try (OutputStream os = exchange.getResponseBody()) {
                        os.write(TEST_DATA_BYTES);
                    }
                } else if (range.startsWith("bytes=")) {
                    // Range request
                    String[] parts = range.substring(6).split("-");
                    int start = Integer.parseInt(parts[0]);
                    int end = parts.length > 1 && !parts[1].isEmpty() ? Integer.parseInt(parts[1]) : TEST_DATA_BYTES.length - 1;
                    
                    if (start >= TEST_DATA_BYTES.length) {
                        exchange.sendResponseHeaders(416, -1);
                        return;
                    }
                    
                    int length = end - start + 1;
                    exchange.getResponseHeaders().set("Content-Range", "bytes " + start + "-" + end + "/" + TEST_DATA_BYTES.length);
                    exchange.sendResponseHeaders(206, length);
                    try (OutputStream os = exchange.getResponseBody()) {
                        os.write(TEST_DATA_BYTES, start, length);
                    }
                } else {
                    exchange.sendResponseHeaders(400, -1);
                }
            }
        });
        server.start();
    }

    @AfterEach
    public void teardown() {
        if (server != null) {
            server.stop(0);
        }
        System.clearProperty("nl.knaw.dans.bagit.hash.chunkSize");
        System.clearProperty("nl.knaw.dans.bagit.hash.maxRetries");
        System.clearProperty("nl.knaw.dans.bagit.hash.retrySleepMs");
    }

    @Test
    public void testHashWithRangeRequests() throws IOException, NoSuchAlgorithmException {
        System.setProperty("nl.knaw.dans.bagit.hash.chunkSize", "10");
        URL url = new URL("http://localhost:" + server.getAddress().getPort() + "/test");
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        
        String hash = Hasher.hash(url, md);
        
        // Expected SHA-1 of TEST_DATA
        MessageDigest expectedMd = MessageDigest.getInstance("SHA-1");
        expectedMd.update(TEST_DATA_BYTES);
        byte[] digest = expectedMd.digest();
        StringBuilder sb = new StringBuilder();
        for (byte b : digest) {
            sb.append(String.format("%02x", b));
        }
        String expectedHash = sb.toString();
        
        Assertions.assertEquals(expectedHash, hash);
        // With chunk size 10 and total length ~90, we expect around 10-11 requests (1 HEAD/initial + chunks)
        Assertions.assertTrue(requestCount.get() > 1);
    }

    @Test
    public void testHashWithRetries() throws IOException, NoSuchAlgorithmException {
        server.removeContext("/test");
        AtomicInteger failCount = new AtomicInteger(0);
        server.createContext("/test", new HttpHandler() {
            @Override
            public void handle(HttpExchange exchange) throws IOException {
                int count = requestCount.incrementAndGet();
                if (count == 2 || count == 3) {
                    // Fail the second and third request (first chunk requests)
                    exchange.sendResponseHeaders(500, -1);
                    return;
                }
                
                String range = exchange.getRequestHeaders().getFirst("Range");
                if (range == null) {
                    exchange.getResponseHeaders().set("Accept-Ranges", "bytes");
                    exchange.getResponseHeaders().set("Content-Length", String.valueOf(TEST_DATA_BYTES.length));
                    exchange.sendResponseHeaders(200, TEST_DATA_BYTES.length);
                    try (OutputStream os = exchange.getResponseBody()) {
                        os.write(TEST_DATA_BYTES);
                    }
                } else {
                    String[] parts = range.substring(6).split("-");
                    int start = Integer.parseInt(parts[0]);
                    int end = parts.length > 1 && !parts[1].isEmpty() ? Integer.parseInt(parts[1]) : TEST_DATA_BYTES.length - 1;
                    int length = end - start + 1;
                    exchange.getResponseHeaders().set("Content-Range", "bytes " + start + "-" + end + "/" + TEST_DATA_BYTES.length);
                    exchange.sendResponseHeaders(206, length);
                    try (OutputStream os = exchange.getResponseBody()) {
                        os.write(TEST_DATA_BYTES, start, length);
                    }
                }
            }
        });

        System.setProperty("nl.knaw.dans.bagit.hash.chunkSize", "20");
        System.setProperty("nl.knaw.dans.bagit.hash.maxRetries", "3");
        System.setProperty("nl.knaw.dans.bagit.hash.retrySleepMs", "100");
        
        URL url = new URL("http://localhost:" + server.getAddress().getPort() + "/test");
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        
        String hash = Hasher.hash(url, md);
        
        MessageDigest expectedMd = MessageDigest.getInstance("SHA-1");
        expectedMd.update(TEST_DATA_BYTES);
        byte[] digest = expectedMd.digest();
        StringBuilder sb = new StringBuilder();
        for (byte b : digest) {
            sb.append(String.format("%02x", b));
        }
        String expectedHash = sb.toString();
        
        Assertions.assertEquals(expectedHash, hash);
        Assertions.assertTrue(requestCount.get() >= 5); // 1 initial + 2 failed + successful chunks
    }

    @Test
    public void testHashWithoutRangeSupport() throws IOException, NoSuchAlgorithmException {
        server.removeContext("/test");
        server.createContext("/test", new HttpHandler() {
            @Override
            public void handle(HttpExchange exchange) throws IOException {
                requestCount.incrementAndGet();
                // No Accept-Ranges header
                exchange.getResponseHeaders().set("Content-Length", String.valueOf(TEST_DATA_BYTES.length));
                exchange.sendResponseHeaders(200, TEST_DATA_BYTES.length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(TEST_DATA_BYTES);
                }
            }
        });

        URL url = new URL("http://localhost:" + server.getAddress().getPort() + "/test");
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        
        String hash = Hasher.hash(url, md);
        
        MessageDigest expectedMd = MessageDigest.getInstance("SHA-1");
        expectedMd.update(TEST_DATA_BYTES);
        byte[] digest = expectedMd.digest();
        StringBuilder sb = new StringBuilder();
        for (byte b : digest) {
            sb.append(String.format("%02x", b));
        }
        String expectedHash = sb.toString();
        
        Assertions.assertEquals(expectedHash, hash);
        // Only 2 requests: 1 HEAD and 1 for full content (openStream)
        Assertions.assertEquals(2, requestCount.get());
    }

    @Test
    public void testHashWithFileUrl() throws IOException, NoSuchAlgorithmException {
        java.nio.file.Path tempFile = java.nio.file.Files.createTempFile("hasher-file-url-test", ".txt");
        try {
            java.nio.file.Files.write(tempFile, TEST_DATA_BYTES);
            URL fileUrl = tempFile.toUri().toURL();
            MessageDigest md = MessageDigest.getInstance("SHA-1");

            String hash = Hasher.hash(fileUrl, md);

            MessageDigest expectedMd = MessageDigest.getInstance("SHA-1");
            expectedMd.update(TEST_DATA_BYTES);
            byte[] digest = expectedMd.digest();
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) {
                sb.append(String.format("%02x", b));
            }
            String expectedHash = sb.toString();

            Assertions.assertEquals(expectedHash, hash);
        } finally {
            java.nio.file.Files.deleteIfExists(tempFile);
        }
    }
}
