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
import nl.knaw.dans.bagit.exceptions.VerificationException;
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
        if (server != null) {
            server.stop(0);
        }
        if (sut != null) {
            sut.close();
        }
    }

    @Test
    public void testIsValidWithExtraHeaders() throws Exception {
        final String content = "test content";
        final String authHeader = "SecretToken";
        
        server.createContext("/data/test.txt", new HttpHandler() {
            @Override
            public void handle(HttpExchange exchange) throws IOException {
                if (authHeader.equals(exchange.getRequestHeaders().getFirst("Authorization"))) {
                    byte[] response = content.getBytes(StandardCharsets.UTF_8);
                    exchange.sendResponseHeaders(200, response.length);
                    try (OutputStream os = exchange.getResponseBody()) {
                        os.write(response);
                    }
                } else {
                    exchange.sendResponseHeaders(401, -1);
                }
            }
        });

        Path bagDir = Files.createTempDirectory(folder, "remote-headers-bag");
        Files.write(bagDir.resolve("bagit.txt"), "BagIt-Version: 0.97\nTag-File-Character-Encoding: UTF-8\n".getBytes());
        Files.createDirectory(bagDir.resolve("data"));
        
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        md5.update(content.getBytes(StandardCharsets.UTF_8));
        String hash = formatMessageDigest(md5.digest());
        
        Files.write(bagDir.resolve("manifest-md5.txt"), (hash + "  data/test.txt\n").getBytes());
        
        URL remoteUrl = new URL("http://localhost:" + port + "/data/test.txt");
        Files.write(bagDir.resolve("fetch.txt"), (remoteUrl.toString() + " - data/test.txt\n").getBytes());
        
        Bag bag = reader.read(bagDir);
        
        // Should fail without headers
        Assertions.assertThrows(VerificationException.class, () -> sut.isValid(bag, true, true));
        
        // Should pass with headers
        Map<String, String> headers = new HashMap<>();
        headers.put("Authorization", authHeader);
        sut.isValid(bag, true, true, headers);
    }

    @Test
    public void testIsValidWithRedirect() throws Exception {
        final String content = "redirected content";
        
        server.createContext("/redirect", new HttpHandler() {
            @Override
            public void handle(HttpExchange exchange) throws IOException {
                exchange.getResponseHeaders().set("Location", "http://localhost:" + port + "/data/final.txt");
                exchange.sendResponseHeaders(302, -1);
            }
        });
        
        server.createContext("/data/final.txt", new HttpHandler() {
            @Override
            public void handle(HttpExchange exchange) throws IOException {
                byte[] response = content.getBytes(StandardCharsets.UTF_8);
                exchange.sendResponseHeaders(200, response.length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(response);
                }
            }
        });

        Path bagDir = Files.createTempDirectory(folder, "remote-redirect-bag");
        Files.write(bagDir.resolve("bagit.txt"), "BagIt-Version: 0.97\nTag-File-Character-Encoding: UTF-8\n".getBytes());
        Files.createDirectory(bagDir.resolve("data"));
        
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        md5.update(content.getBytes(StandardCharsets.UTF_8));
        String hash = formatMessageDigest(md5.digest());
        
        Files.write(bagDir.resolve("manifest-md5.txt"), (hash + "  data/test.txt\n").getBytes());
        
        URL redirectUrl = new URL("http://localhost:" + port + "/redirect");
        Files.write(bagDir.resolve("fetch.txt"), (redirectUrl.toString() + " - data/test.txt\n").getBytes());
        
        Bag bag = reader.read(bagDir);
        
        sut.isValid(bag, true, true);
    }

    private String formatMessageDigest(final byte[] digest) {
        StringBuilder sb = new StringBuilder();
        for (byte b : digest) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
