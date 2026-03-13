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

public class BagVerifierUrlConfigTest extends TempFolderTest {
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
    public void testUrlSpecificHeaders() throws Exception {
        final String content = "test content";
        final String globalHeaderName = "X-Global";
        final String globalHeaderValue = "global-val";
        final String urlHeaderName = "X-Url-Specific";
        final String urlHeaderValue = "url-val";
        
        final AtomicBoolean globalReceived = new AtomicBoolean(false);
        final AtomicBoolean urlSpecificReceived = new AtomicBoolean(false);

        server.createContext("/specific", new HttpHandler() {
            @Override
            public void handle(HttpExchange exchange) throws IOException {
                if (globalHeaderValue.equals(exchange.getRequestHeaders().getFirst(globalHeaderName))) {
                    globalReceived.set(true);
                }
                if (urlHeaderValue.equals(exchange.getRequestHeaders().getFirst(urlHeaderName))) {
                    urlSpecificReceived.set(true);
                }
                
                byte[] response = content.getBytes(StandardCharsets.UTF_8);
                exchange.sendResponseHeaders(200, response.length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(response);
                }
            }
        });

        Path bagDir = Files.createTempDirectory(folder, "url-config-bag");
        Files.write(bagDir.resolve("bagit.txt"), "BagIt-Version: 0.97\nTag-File-Character-Encoding: UTF-8\n".getBytes());
        Files.createDirectory(bagDir.resolve("data"));
        
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        sha1.update(content.getBytes(StandardCharsets.UTF_8));
        String hash = formatMessageDigest(sha1.digest());
        
        Files.write(bagDir.resolve("manifest-sha1.txt"), (hash + "  data/test.txt\n").getBytes());
        
        URL remoteUrl = new URL("http://localhost:" + port + "/specific");
        Files.write(bagDir.resolve("fetch.txt"), (remoteUrl.toString() + " " + content.length() + " data/test.txt\n").getBytes());
        
        Bag bag = reader.read(bagDir);
        
        Map<String, String> globalHeaders = new HashMap<>();
        globalHeaders.put(globalHeaderName, globalHeaderValue);
        
        Map<String, Map<String, String>> urlConfigs = new HashMap<>();
        Map<String, String> specificHeaders = new HashMap<>();
        specificHeaders.put(urlHeaderName, urlHeaderValue);
        urlConfigs.put("http://localhost:" + port + "/specific", specificHeaders);
        
        sut.isValid(bag, true, true, globalHeaders, urlConfigs);

        Assertions.assertTrue(globalReceived.get(), "Global header should have been received");
        Assertions.assertTrue(urlSpecificReceived.get(), "URL specific header should have been received");
    }

    @Test
    public void testUrlPrefixMatching() throws Exception {
        final String content = "test content";
        final String headerName = "X-Url-Specific";
        final String headerValue = "url-val";
        
        final AtomicBoolean headerReceived = new AtomicBoolean(false);

        server.createContext("/prefix/specific", new HttpHandler() {
            @Override
            public void handle(HttpExchange exchange) throws IOException {
                if (headerValue.equals(exchange.getRequestHeaders().getFirst(headerName))) {
                    headerReceived.set(true);
                }
                
                byte[] response = content.getBytes(StandardCharsets.UTF_8);
                exchange.sendResponseHeaders(200, response.length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(response);
                }
            }
        });

        Path bagDir = Files.createTempDirectory(folder, "url-prefix-bag");
        Files.write(bagDir.resolve("bagit.txt"), "BagIt-Version: 0.97\nTag-File-Character-Encoding: UTF-8\n".getBytes());
        Files.createDirectory(bagDir.resolve("data"));
        
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        sha1.update(content.getBytes(StandardCharsets.UTF_8));
        String hash = formatMessageDigest(sha1.digest());
        
        Files.write(bagDir.resolve("manifest-sha1.txt"), (hash + "  data/test.txt\n").getBytes());
        
        URL remoteUrl = new URL("http://localhost:" + port + "/prefix/specific");
        Files.write(bagDir.resolve("fetch.txt"), (remoteUrl.toString() + " " + content.length() + " data/test.txt\n").getBytes());
        
        Bag bag = reader.read(bagDir);
        
        Map<String, Map<String, String>> urlConfigs = new HashMap<>();
        Map<String, String> specificHeaders = new HashMap<>();
        specificHeaders.put(headerName, headerValue);
        // Using a prefix
        urlConfigs.put("http://localhost:" + port + "/prefix", specificHeaders);
        
        sut.isValid(bag, true, true, null, urlConfigs);

        Assertions.assertTrue(headerReceived.get(), "URL specific header should have been received because of prefix match");
    }

    @Test
    public void testMultipleUrlConfigs() throws Exception {
        final String content1 = "content 1";
        final String content2 = "content 2";
        final String header1 = "X-H1";
        final String header2 = "X-H2";
        
        final AtomicBoolean h1Received = new AtomicBoolean(false);
        final AtomicBoolean h2Received = new AtomicBoolean(false);

        server.createContext("/url1", new HttpHandler() {
            @Override
            public void handle(HttpExchange exchange) throws IOException {
                if ("v1".equals(exchange.getRequestHeaders().getFirst(header1))) h1Received.set(true);
                byte[] response = content1.getBytes(StandardCharsets.UTF_8);
                exchange.sendResponseHeaders(200, response.length);
                try (OutputStream os = exchange.getResponseBody()) { os.write(response); }
            }
        });
        server.createContext("/url2", new HttpHandler() {
            @Override
            public void handle(HttpExchange exchange) throws IOException {
                if ("v2".equals(exchange.getRequestHeaders().getFirst(header2))) h2Received.set(true);
                byte[] response = content2.getBytes(StandardCharsets.UTF_8);
                exchange.sendResponseHeaders(200, response.length);
                try (OutputStream os = exchange.getResponseBody()) { os.write(response); }
            }
        });

        Path bagDir = Files.createTempDirectory(folder, "multi-url-bag");
        Files.write(bagDir.resolve("bagit.txt"), "BagIt-Version: 0.97\nTag-File-Character-Encoding: UTF-8\n".getBytes());
        Files.createDirectory(bagDir.resolve("data"));
        
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        
        sha1.update(content1.getBytes(StandardCharsets.UTF_8));
        String hash1 = formatMessageDigest(sha1.digest());
        sha1.reset();
        sha1.update(content2.getBytes(StandardCharsets.UTF_8));
        String hash2 = formatMessageDigest(sha1.digest());
        
        Files.write(bagDir.resolve("manifest-sha1.txt"), (hash1 + "  data/t1.txt\n" + hash2 + "  data/t2.txt\n").getBytes());
        
        URL url1 = new URL("http://localhost:" + port + "/url1");
        URL url2 = new URL("http://localhost:" + port + "/url2");
        Files.write(bagDir.resolve("fetch.txt"), (url1 + " " + content1.length() + " data/t1.txt\n" + url2 + " " + content2.length() + " data/t2.txt\n").getBytes());
        
        Bag bag = reader.read(bagDir);
        
        Map<String, Map<String, String>> urlConfigs = new HashMap<>();
        Map<String, String> s1 = new HashMap<>(); s1.put(header1, "v1");
        Map<String, String> s2 = new HashMap<>(); s2.put(header2, "v2");
        urlConfigs.put(url1.toString(), s1);
        urlConfigs.put(url2.toString(), s2);
        
        sut.isValid(bag, true, true, null, urlConfigs);

        Assertions.assertTrue(h1Received.get(), "Header 1 should have been received");
        Assertions.assertTrue(h2Received.get(), "Header 2 should have been received");
    }

    private String formatMessageDigest(final byte[] digest) {
        StringBuilder sb = new StringBuilder();
        for (byte b : digest) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
