/*
 * Copyright IBM Corp. 2025, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.jmh;

import java.io.File;
import java.io.IOException;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.TearDown;
import org.openjdk.jmh.annotations.Warmup;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;

@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
@State(Scope.Thread)
@Warmup(iterations = 3, time = 10, timeUnit = TimeUnit.SECONDS)
@Measurement(iterations = 4, time = 30, timeUnit = TimeUnit.SECONDS)
@Fork(1)
public class TLSHandshakeBenchmark extends JMHBase {

    @Param({"X25519", "X25519MLKEM768"})
    //@Param({"X25519"})
    public String namedGroup;

    @Param({"true", "false"})
    public boolean useCache;

    private static final String CIPHER_SUITE = "TLS_AES_256_GCM_SHA384";

    private SSLServerSocket serverSocket;
    private SSLContext sslContext;
    private SSLSocketFactory clientFactory;
    private int port;
    private Thread serverThread;
    private volatile boolean serverReady = false;
    private SSLSession cachedSession;

    @Setup(Level.Trial)
    public void setup() throws Exception {
        super.setup("OpenJCEPlus");
        System.out.println("HERE!!!");

        generateKeyStore();

        System.setProperty("javax.net.ssl.keyStore", "testkeys.p12");
        System.setProperty("javax.net.ssl.keyStorePassword", "password");
        System.setProperty("javax.net.ssl.trustStore", "testkeys.p12");
        System.setProperty("javax.net.ssl.trustStorePassword", "password");

        // Create a shared SSLContext for session caching
        sslContext = SSLContext.getDefault();
        
        SSLServerSocketFactory ssf = (SSLServerSocketFactory) sslContext.getServerSocketFactory();
        serverSocket = (SSLServerSocket) ssf.createServerSocket(0);

        serverSocket.setEnabledCipherSuites(new String[]{CIPHER_SUITE});
        serverSocket.setEnabledProtocols(new String[]{"TLSv1.3"});
        
        port = serverSocket.getLocalPort();
        clientFactory = (SSLSocketFactory) sslContext.getSocketFactory();

        // Capture the current namedGroup value for this trial
        final String currentNamedGroup = namedGroup;
        
        serverThread = new Thread(() -> {
            serverReady = true;
            while (!Thread.interrupted()) {
                try {
                    SSLSocket socket = (SSLSocket) serverSocket.accept();
                    socket.setEnabledProtocols(new String[]{"TLSv1.3"});
                    socket.setEnabledCipherSuites(new String[]{CIPHER_SUITE});
                    
                    // Set named groups if the method is available (Java 13+)
                    try {
                        SSLParameters params = socket.getSSLParameters();
                        params.setNamedGroups(new String[]{currentNamedGroup});
                        socket.setSSLParameters(params);
                    } catch (NoSuchMethodError e) {
                        // setNamedGroups not available in this Java version, skip it
                    }
                    
                    socket.startHandshake();
                    socket.getInputStream().read();
                    // Write back to client so it can complete reading and receive NewSessionTicket
                    socket.getOutputStream().write(1);
                    socket.getOutputStream().flush();
                    socket.close();
                    
                } catch (IOException e) {
                    if (!Thread.interrupted()) {
                        // Only log if not intentionally interrupted
                        e.printStackTrace();
                    }
                }
            }
        });
        serverThread.setDaemon(true);
        serverThread.start();
        
        // Wait for server to be ready
        while (!serverReady) {
            Thread.sleep(10);
        }
        // Give server a bit more time to fully initialize
        Thread.sleep(100);
    }

    @TearDown(Level.Trial)
    public void tearDown() throws Exception {
        // Close the server socket first to unblock accept()
        if (serverSocket != null && !serverSocket.isClosed()) {
            try {
                serverSocket.close();
            } catch (IOException e) {
                // Ignore close exceptions during teardown
            }
        }
        
        // Then interrupt and wait for the server thread to finish
        if (serverThread != null) {
            serverThread.interrupt();
            try {
                serverThread.join(1000); // Wait up to 1 second for thread to finish
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    @Benchmark
    public void testHandshake() throws Exception {
        SSLSocket clientSocket = null;
        try {
            // Create a new socket for each handshake
            clientSocket = (SSLSocket) clientFactory.createSocket("localhost", port);
            clientSocket.setEnabledProtocols(new String[]{"TLSv1.3"});
            clientSocket.setEnabledCipherSuites(new String[]{CIPHER_SUITE});

            // Set named groups if the method is available (Java 13+)
            try {
                SSLParameters params = clientSocket.getSSLParameters();
                params.setNamedGroups(new String[]{namedGroup});
                clientSocket.setSSLParameters(params);
            } catch (NoSuchMethodError e) {
                // setNamedGroups not available in this Java version, skip it
            }

            clientSocket.startHandshake();

            clientSocket.getOutputStream().write(1);
            
            // In TLS 1.3, the server sends NewSessionTicket after handshake completion.
            // Reading from the socket ensures we receive the NewSessionTicket before closing.
            // This is critical for session resumption to work properly.
            clientSocket.getInputStream().read();

            if (useCache) {
                // Cache the session for reuse in subsequent handshakes
                cachedSession = clientSocket.getSession();
            } else {
                // Invalidate the session to force full handshake
                clientSocket.getSession().invalidate();
            }
        } finally {
            if (clientSocket != null) {
                clientSocket.close();
            }
        }
    }

    private void generateKeyStore() throws Exception {
        File keystoreFile = new File("testkeys.p12");
        if (keystoreFile.exists()) {
            return; 
        }

        System.out.println("Generating testkeys keystore with EC...");
        ProcessBuilder processBuilder = new ProcessBuilder(
                "keytool",
                "-genkeypair",
                "-keyalg", "EC",
                "-keysize", "256",
                "-validity", "365",
                "-keystore", "testkeys.p12",
                "-storetype", "PKCS12",
                "-storepass", "password",
                "-keypass", "password",
                "-dname", "CN=localhost"
        );

        processBuilder.inheritIO();
        Process process = processBuilder.start();
        int exitCode = process.waitFor();

        if (exitCode != 0) {
            throw new RuntimeException("Failed to generate testkeys using keytool. Exit code: " + exitCode);
        }
    }

    public static void main(String[] args) throws RunnerException {
        String testSimpleName = TLSHandshakeBenchmark.class.getSimpleName();
        Options opt = optionsBuild(testSimpleName, testSimpleName);

        new Runner(opt).run();
    }
}
