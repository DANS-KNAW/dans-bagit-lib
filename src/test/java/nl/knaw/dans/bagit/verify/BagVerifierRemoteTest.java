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

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import nl.knaw.dans.bagit.TempFolderTest;
import nl.knaw.dans.bagit.domain.Bag;
import nl.knaw.dans.bagit.reader.BagReader;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

public class BagVerifierRemoteTest extends TempFolderTest {
    private HttpServer server;
    private BagVerifier sut;
    private BagReader reader;
    private int port;

    @BeforeEach
    public void setup() throws IOException {
        sut = new BagVerifier();
        reader = new BagReader();
        server = HttpServer.create(new InetSocketAddress(0), 0);
        server.setExecutor(null);
        server.start();
        port = server.getAddress().getPort();
    }

    @AfterEach
    public void tearDown() {
        if (server != null) server.stop(0);
        if (sut != null) sut.close();
    }

    @Test
    public void testAuthenticatedRangeRequest() throws Exception {
        final String content = "this is some test content for range requests";
        final String authHeaderName = "X-Dataverse-key";
        final String authHeaderValue = "secret-key";
        final AtomicInteger rangeRequestCount = new AtomicInteger(0);

        server.createContext("/datafile", new HttpHandler() {
            @Override
            public void handle(HttpExchange exchange) throws IOException {
                if (!authHeaderValue.equals(exchange.getRequestHeaders().getFirst(authHeaderName))) {
                    exchange.sendResponseHeaders(401, -1);
                    return;
                }

                String range = exchange.getRequestHeaders().getFirst("Range");
                if (range != null && range.startsWith("bytes=")) {
                    rangeRequestCount.incrementAndGet();
                    String[] parts = range.substring(6).split("-");
                    int start = Integer.parseInt(parts[0]);
                    int end = Integer.parseInt(parts[1]);
                    byte[] fullContent = content.getBytes(StandardCharsets.UTF_8);
                    int actualEnd = Math.min(end, fullContent.length - 1);
                    int length = actualEnd - start + 1;
                    
                    exchange.getResponseHeaders().set("Content-Range", "bytes " + start + "-" + actualEnd + "/" + fullContent.length);
                    exchange.sendResponseHeaders(206, length);
                    try (OutputStream os = exchange.getResponseBody()) {
                        os.write(fullContent, start, length);
                    }
                } else {
                    byte[] response = content.getBytes(StandardCharsets.UTF_8);
                    exchange.sendResponseHeaders(200, response.length);
                    try (OutputStream os = exchange.getResponseBody()) {
                        os.write(response);
                    }
                }
            }
        });

        Path bagDir = Files.createTempDirectory(folder, "remote-bag");
        Files.write(bagDir.resolve("bagit.txt"), "BagIt-Version: 0.97\nTag-File-Character-Encoding: UTF-8\n".getBytes());
        Files.createDirectory(bagDir.resolve("data"));
        
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        sha1.update(content.getBytes(StandardCharsets.UTF_8));
        String hash = formatMessageDigest(sha1.digest());
        
        Files.write(bagDir.resolve("manifest-sha1.txt"), (hash + "  data/test.txt\n").getBytes());
        
        URL remoteUrl = new URL("http://localhost:" + port + "/datafile");
        Files.write(bagDir.resolve("fetch.txt"), (remoteUrl.toString() + " " + content.length() + " data/test.txt\n").getBytes());
        
        Bag bag = reader.read(bagDir);
        
        Map<String, String> headers = new HashMap<>();
        headers.put(authHeaderName, authHeaderValue);
        
        // Use a small chunk size to force multiple range requests
        System.setProperty("nl.knaw.dans.bagit.hash.chunkSize", "10");
        try {
            sut.isValid(bag, true, true, headers);
        } finally {
            System.clearProperty("nl.knaw.dans.bagit.hash.chunkSize");
        }

        Assertions.assertTrue(rangeRequestCount.get() > 1, "Should have used multiple range requests, but used: " + rangeRequestCount.get());
    }

    @Test
    public void testFallbackToFullDownloadWhenRangeNotSupported() throws Exception {
        final String content = "this content will be downloaded in one go";
        final AtomicBoolean rangeAttempted = new AtomicBoolean(false);

        server.createContext("/datafile", new HttpHandler() {
            @Override
            public void handle(HttpExchange exchange) throws IOException {
                if (exchange.getRequestHeaders().containsKey("Range")) {
                    rangeAttempted.set(true);
                    // Server ignores range and returns 200 OK
                    byte[] response = content.getBytes(StandardCharsets.UTF_8);
                    exchange.sendResponseHeaders(200, response.length);
                    try (OutputStream os = exchange.getResponseBody()) {
                        os.write(response);
                    }
                } else {
                    byte[] response = content.getBytes(StandardCharsets.UTF_8);
                    exchange.sendResponseHeaders(200, response.length);
                    try (OutputStream os = exchange.getResponseBody()) {
                        os.write(response);
                    }
                }
            }
        });

        Path bagDir = Files.createTempDirectory(folder, "remote-bag-fallback");
        Files.write(bagDir.resolve("bagit.txt"), "BagIt-Version: 0.97\nTag-File-Character-Encoding: UTF-8\n".getBytes());
        Files.createDirectory(bagDir.resolve("data"));
        
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        sha1.update(content.getBytes(StandardCharsets.UTF_8));
        String hash = formatMessageDigest(sha1.digest());
        
        Files.write(bagDir.resolve("manifest-sha1.txt"), (hash + "  data/test.txt\n").getBytes());
        
        URL remoteUrl = new URL("http://localhost:" + port + "/datafile");
        Files.write(bagDir.resolve("fetch.txt"), (remoteUrl.toString() + " " + content.length() + " data/test.txt\n").getBytes());
        
        Bag bag = reader.read(bagDir);
        
        sut.isValid(bag, true, true, null);

        Assertions.assertTrue(rangeAttempted.get(), "Should have attempted a range request");
    }

    private String formatMessageDigest(final byte[] digest) {
        StringBuilder sb = new StringBuilder();
        for (byte b : digest) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
