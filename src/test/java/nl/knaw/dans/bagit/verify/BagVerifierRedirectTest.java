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

public class BagVerifierRedirectTest extends TempFolderTest {
    private HttpServer server1;
    private HttpServer server2;
    private BagVerifier sut;
    private BagReader reader;
    private int port1;
    private int port2;

    @BeforeEach
    public void setup() throws IOException {
        sut = new BagVerifier();
        reader = new BagReader();
        
        server1 = HttpServer.create(new InetSocketAddress(0), 0);
        server1.setExecutor(null);
        server1.start();
        port1 = server1.getAddress().getPort();

        server2 = HttpServer.create(new InetSocketAddress(0), 0);
        server2.setExecutor(null);
        server2.start();
        port2 = server2.getAddress().getPort();
    }

    @AfterEach
    public void tearDown() {
        if (server1 != null) server1.stop(0);
        if (server2 != null) server2.stop(0);
        if (sut != null) sut.close();
    }

    @Test
    public void testRedirectStripsHeadersOnHostChange() throws Exception {
        final String content = "final content";
        final String authHeaderName = "X-Dataverse-key";
        final String authHeaderValue = "secret";
        final AtomicBoolean headersSentToServer2 = new AtomicBoolean(false);

        // Server 1 redirects to Server 2
        server1.createContext("/api/access/datafile/1", new HttpHandler() {
            @Override
            public void handle(HttpExchange exchange) throws IOException {
                System.out.println("[DEBUG_LOG] Server 1 received request with headers: " + exchange.getRequestHeaders().entrySet());
                if (authHeaderValue.equals(exchange.getRequestHeaders().getFirst(authHeaderName))) {
                    exchange.getResponseHeaders().set("Location", "http://localhost:" + port2 + "/storage/file1?token=xyz");
                    exchange.sendResponseHeaders(302, -1);
                } else {
                    exchange.sendResponseHeaders(401, -1);
                }
            }
        });

        // Server 2 returns content but fails if auth header is present
        server2.createContext("/storage/file1", new HttpHandler() {
            @Override
            public void handle(HttpExchange exchange) throws IOException {
                System.out.println("[DEBUG_LOG] Server 2 received request with headers: " + exchange.getRequestHeaders().entrySet());
                if (exchange.getRequestHeaders().containsKey(authHeaderName)) {
                    headersSentToServer2.set(true);
                    // Simulate 403 Forbidden because S3 rejects requests with unknown/extra auth headers
                    exchange.sendResponseHeaders(403, -1);
                } else {
                    byte[] response = content.getBytes(StandardCharsets.UTF_8);
                    exchange.sendResponseHeaders(200, response.length);
                    try (OutputStream os = exchange.getResponseBody()) {
                        os.write(response);
                    }
                }
            }
        });

        Path bagDir = Files.createTempDirectory(folder, "redirect-headers-bag");
        Files.write(bagDir.resolve("bagit.txt"), "BagIt-Version: 0.97\nTag-File-Character-Encoding: UTF-8\n".getBytes());
        Files.createDirectory(bagDir.resolve("data"));
        
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        md5.update(content.getBytes(StandardCharsets.UTF_8));
        String hash = formatMessageDigest(md5.digest());
        
        Files.write(bagDir.resolve("manifest-md5.txt"), (hash + "  data/test.txt\n").getBytes());
        
        URL remoteUrl = new URL("http://localhost:" + port1 + "/api/access/datafile/1");
        Files.write(bagDir.resolve("fetch.txt"), (remoteUrl.toString() + " - data/test.txt\n").getBytes());
        
        Bag bag = reader.read(bagDir);
        
        Map<String, String> headers = new HashMap<>();
        headers.put(authHeaderName, authHeaderValue);
        
        // This should now PASS because Hasher.java strips headers on host change
        sut.isValid(bag, true, true, headers);

        Assertions.assertFalse(headersSentToServer2.get(), "Headers should NOT have been sent to server2");
    }

    private String formatMessageDigest(final byte[] digest) {
        StringBuilder sb = new StringBuilder();
        for (byte b : digest) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
