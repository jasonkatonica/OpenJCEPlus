/*
 * Copyright IBM Corp. 2023, 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit;

import org.junit.jupiter.api.Test;
import org.junit.platform.launcher.Launcher;
import org.junit.platform.launcher.LauncherDiscoveryRequest;
import org.junit.platform.launcher.core.LauncherDiscoveryRequestBuilder;
import org.junit.platform.launcher.core.LauncherFactory;
import org.junit.platform.launcher.listeners.SummaryGeneratingListener;
import static org.junit.platform.engine.discovery.DiscoverySelectors.selectClass;

public class TestInLoop {

    @Test
    public void test() throws Exception {
        System.out.println("Running tests!!!!!");
        for (int x = 0;x <= 5; x++) {
            System.out.println("Calling test suite.");
            runTest("ibm.jceplus.junit.openjceplus.TestAll");
        }
        System.out.println("Now sleeping PID: " + ProcessHandle.current().pid());
        Thread.sleep(100000000);
    }

    private void runTest(String className) {
        Launcher launcher = LauncherFactory.create();
        SummaryGeneratingListener listener = new SummaryGeneratingListener();
        launcher.registerTestExecutionListeners(listener);
        LauncherDiscoveryRequest request = LauncherDiscoveryRequestBuilder.request().
            selectors(selectClass(className)).build();
        launcher.execute(request);
    }
}
