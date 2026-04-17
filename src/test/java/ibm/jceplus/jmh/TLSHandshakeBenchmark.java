/*
 * Copyright IBM Corp. 2026, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.jmh;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.SocketTimeoutException;
import java.security.KeyStore;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.TearDown;
import org.openjdk.jmh.annotations.Threads;
import org.openjdk.jmh.annotations.Warmup;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;

@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
@State(Scope.Benchmark)
@Warmup(iterations = 3, time = 10, timeUnit = TimeUnit.SECONDS)
@Measurement(iterations = 4, time = 30, timeUnit = TimeUnit.SECONDS)
@Threads(1) // Vital: Prevents multiple clients from deadlocking a single-threaded server
public class TLSHandshakeBenchmark extends JMHBase {

    private static final String PAYLOAD_1KB = "1024";

    @Param({"X25519", "X25519MLKEM768", "SecP256r1", "SecP256r1MLKEM768", "SecP384r1", "SecP384r1MLKEM1024"})
    public String namedGroup;

    @Param({"cached", "non-cached"})
    public String useCache;

    @Param({"TLS_AES_256_GCM_SHA384"})
    public String cipherSuite;

    @Param({PAYLOAD_1KB})
    public int payload;

    @Param({"OpenJCEPlus", "SunJCE"})
    private String provider;

    private SSLServerSocket serverSocket;
    private SSLContext sslContext;
    private SSLSocketFactory clientFactory;
    private int port;
    private Thread serverThread;
    private ExecutorService executor;

    @Setup(Level.Trial)
    public void setup() throws Exception {
        super.setup(provider);

        generateKeyStore();
        
        // Create ExecutorService for handling client connections (max 10 threads)
        executor = Executors.newFixedThreadPool(10);

        // Load keystore and truststore programmatically
        String keystorePath = "testkeys.p12";
        String keystorePassword = "password";
        
        // Load the keystore
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(keystorePath)) {
            keyStore.load(fis, keystorePassword.toCharArray());
        }
        
        // Initialize KeyManagerFactory
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, keystorePassword.toCharArray());
        
        // Initialize TrustManagerFactory
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(keyStore);

        // Create SSLContext with the key and trust managers
        sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        
        SSLServerSocketFactory ssf = (SSLServerSocketFactory) sslContext.getServerSocketFactory();
        serverSocket = (SSLServerSocket) ssf.createServerSocket(0);

        serverSocket.setEnabledCipherSuites(new String[]{cipherSuite});
        serverSocket.setEnabledProtocols(new String[]{"TLSv1.3"});
        
        port = serverSocket.getLocalPort();
        clientFactory = (SSLSocketFactory) sslContext.getSocketFactory();

        // Capture the current namedGroup and payload values for this trial
        final String currentNamedGroup = namedGroup;
        final int currentPayload = payload;
        
        serverThread = new Thread(() -> {
            while (!Thread.interrupted()) {
                try {
                    SSLSocket socket = (SSLSocket) serverSocket.accept();
                    executor.submit(() -> handleClient(socket, currentNamedGroup, currentPayload));
                } catch (IOException e) {
                    if (!Thread.interrupted() && !serverSocket.isClosed()) {
                        // Only log if not intentionally interrupted or socket closed
                        e.printStackTrace();
                    }
                    if (serverSocket.isClosed()) {
                        break;
                    }
                }
            }
        });
        serverThread.setDaemon(true);
        serverThread.start();
        
        Thread.sleep(500); // Wait for server to bind
    }

    @Benchmark
    public byte[] testHandshake() throws Exception {
        try (SSLSocket clientSocket = (SSLSocket) clientFactory.createSocket("localhost", port)) {
            // Set socket timeout to prevent hanging (5 minutes)
            clientSocket.setSoTimeout(300000);
            
            clientSocket.setEnabledProtocols(new String[]{"TLSv1.3"});
            clientSocket.setEnabledCipherSuites(new String[]{cipherSuite});

            SSLParameters params = clientSocket.getSSLParameters();
            params.setNamedGroups(new String[]{namedGroup});
            clientSocket.setSSLParameters(params);

            clientSocket.startHandshake();
            
            OutputStream os = clientSocket.getOutputStream();
            InputStream is = clientSocket.getInputStream();

            os.write(new byte[payload]);
            os.flush();

            byte[] response = is.readNBytes(payload);
            
            if ("non-cached".equals(useCache)) {
                // Invalidate the session to force full handshake
                clientSocket.getSession().invalidate();
            }
            
            return response; // Prevents Dead Code Elimination
        } catch (SocketTimeoutException e) {
            System.err.println("ERROR: Client socket timeout occurred after 5 minutes - this is unexpected!");
            e.printStackTrace();
            throw e;
        }
    }

    private void handleClient(SSLSocket socket, String currentNamedGroup, int currentPayload) {
        try {
            // Set socket timeout to prevent hanging (5 minutes)
            socket.setSoTimeout(300000);
            
            socket.setEnabledProtocols(new String[]{"TLSv1.3"});
            socket.setEnabledCipherSuites(new String[]{cipherSuite});
            
            // Set named groups if the method is available (Java 19+)
            SSLParameters params = socket.getSSLParameters();
            params.setNamedGroups(new String[]{currentNamedGroup});
            socket.setSSLParameters(params);
            
            socket.startHandshake();

            // Read exactly 'payload' bytes
            InputStream is = socket.getInputStream();
            byte[] buffer = is.readNBytes(currentPayload);
            
            // Write back the response
            OutputStream os = socket.getOutputStream();
            os.write(buffer);
            os.flush();
            
            socket.close();
        } catch (SocketTimeoutException e) {
            System.err.println("ERROR: Server socket timeout occurred after 5 minutes - this is unexpected!");
            e.printStackTrace();
            throw new RuntimeException("Server timeout - terminating benchmark", e);
        } catch (IOException e) {
            if (!Thread.interrupted() && !serverSocket.isClosed()) {
                e.printStackTrace();
            }
        }
    }

    @TearDown(Level.Trial)
    public void tearDown() throws Exception {
        if (serverSocket != null) {
            serverSocket.close();
        }
        if (serverThread != null) {
            serverThread.join(2000);
        }
        if (executor != null) {
            executor.shutdown();
            try {
                if (!executor.awaitTermination(5, TimeUnit.SECONDS)) {
                    executor.shutdownNow();
                }
            } catch (InterruptedException e) {
                executor.shutdownNow();
                Thread.currentThread().interrupt();
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
