/*
 * Copyright IBM Corp. 2023, 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.jmh;

import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;

public class RunAll extends OpenJCEPlusJMHBase {

    public static void main(String[] args) throws RunnerException {
        Options opt = optionsBuild(
            "Benchmark",
            RunAll.class.getSimpleName());
        new Runner(opt).run();
    }
}
