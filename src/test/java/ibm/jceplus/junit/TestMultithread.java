/*
 * Copyright IBM Corp. 2023, 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import org.junit.platform.launcher.Launcher;
import org.junit.platform.launcher.LauncherDiscoveryRequest;
import org.junit.platform.launcher.core.LauncherDiscoveryRequestBuilder;
import org.junit.platform.launcher.core.LauncherFactory;
import org.junit.platform.launcher.listeners.SummaryGeneratingListener;
import org.junit.platform.launcher.listeners.TestExecutionSummary;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.platform.engine.discovery.DiscoverySelectors.selectClass;

@TestInstance(Lifecycle.PER_CLASS)
public class TestMultithread {
    private final int numThreads = 20;
    private final int timeoutSec = 200000;
    private final String[] testList = {
            "ibm.jceplus.junit.openjceplus.multithread.TestAESGCMUpdate"};

    public TestMultithread() {}

    private boolean assertConcurrent(final String message, final Callable<List<TestExecutionSummary.Failure>> callable,
            final int maxTimeoutSeconds) throws InterruptedException {
        boolean failed = false;
        final List<Throwable> exceptions = Collections.synchronizedList(new ArrayList<Throwable>());
        final List<TestExecutionSummary.Failure> failures = Collections.synchronizedList(new ArrayList<TestExecutionSummary.Failure>());
        final ExecutorService threadPool = Executors.newFixedThreadPool(numThreads);
        try {
            final CountDownLatch allExecutorThreadsReady = new CountDownLatch(numThreads);
            final CountDownLatch afterInitBlocker = new CountDownLatch(1);
            final CountDownLatch allDone = new CountDownLatch(numThreads);
            for (int i = 0; i < numThreads; i++) {
                threadPool.submit(new Runnable() {
                    public void run() {
                        allExecutorThreadsReady.countDown();
                        try {
                            afterInitBlocker.await();
                            failures.addAll(callable.call());
                        } catch (final Throwable e) {
                            exceptions.add(e);
                        } finally {
                            allDone.countDown();
                        }
                    }
                });
            }
            // wait until all threads are ready
            assertTrue(
                    allExecutorThreadsReady.await(numThreads * 100, TimeUnit.MILLISECONDS),
                    "Timeout initializing threads! Perform long lasting initializations before passing runnables to assertConcurrent");
            // start all test runners
            afterInitBlocker.countDown();
            assertTrue(
                    allDone.await(maxTimeoutSeconds, TimeUnit.SECONDS),
                    message + " timeout! More than " + maxTimeoutSeconds + " seconds");
        } finally {
            threadPool.shutdownNow();
        }
        if (!exceptions.isEmpty()) {
            for (Throwable t : exceptions) {
                t.printStackTrace();
            }
        }
        failed = !exceptions.isEmpty();

        for (TestExecutionSummary.Failure failure : failures) {
            failure.getException().printStackTrace();
        }
        failed = !failures.isEmpty();

        return failed;
    }

    private Callable<List<TestExecutionSummary.Failure>> testToCallable(String className) {
        SummaryGeneratingListener listener = new SummaryGeneratingListener();
        LauncherDiscoveryRequest request = LauncherDiscoveryRequestBuilder.request().
            selectors(selectClass(className)).build();
        
        Launcher launcher = LauncherFactory.create();
        launcher.discover(request);
        launcher.registerTestExecutionListeners(listener);

        return new Callable<List<TestExecutionSummary.Failure>>() {
            public List<TestExecutionSummary.Failure> call() {
                launcher.execute(request);
                return listener.getSummary().getFailures();
            }
        };
    }

    @AfterAll
    public void afterall() throws Exception {
        //System.out.println("Now sleeping with PID: " + ProcessHandle.current().pid());
        //Thread.sleep(100000000);
    }

    @Test
    public void testMultithread() {
        System.out.println("#threads=" + numThreads + " timeout=" + timeoutSec);

        List<String> failedTests = new ArrayList<>();

        for (String test : testList) {
            try {
                System.out.println("Test calling: " + test);

                boolean failed = assertConcurrent("Test failed: " + test, testToCallable(test), timeoutSec);
                if (failed) {
                    failedTests.add(test);
                }

            } catch (InterruptedException e) {
                //System.out.println("Test interrupted: " + e);
            }
            System.out.println("Test finished: " + test);
            if (!failedTests.isEmpty()) {
                String allFailedTests = String.join("\n\t", failedTests);
                fail("Failed tests:\n\t" + allFailedTests);
            }
        }
    }
}
