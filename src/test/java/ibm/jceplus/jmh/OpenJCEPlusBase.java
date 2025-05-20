/*
 * Copyright IBM Corp. 2023, 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */
package ibm.jceplus.jmh;

import java.io.File;
import java.net.URL;
import java.net.URLClassLoader;
import java.security.Provider;
import org.openjdk.jmh.profile.ClassloaderProfiler;
import org.openjdk.jmh.profile.CompilerProfiler;
import org.openjdk.jmh.profile.GCProfiler;
import org.openjdk.jmh.profile.StackProfiler;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

abstract public class OpenJCEPlusBase {

    protected static Options optionsBuild(String regexClassName, String logFileRoot) {
        // This is necessary to pass various classpath values to the forked JVM we are about to create.
        URLClassLoader classLoader = (URLClassLoader) SHA256Benchmark.class.getClassLoader();
        StringBuilder classpath = new StringBuilder();
        for(URL url : classLoader.getURLs()) {
            classpath.append(url.getPath()).append(File.pathSeparator);
        }
        System.setProperty("java.class.path", classpath.toString());

        // Get properties needed to build options.
        String projectHomeDir = System.getProperty("jmh.project.dir");
        System.out.println("Home dir: " + projectHomeDir);
        System.out.println("Regex of classes to run: " + regexClassName);

        Options opt = new OptionsBuilder()
                .include(regexClassName)
                .resultFormat(org.openjdk.jmh.results.format.ResultFormatType.CSV)
                .result(projectHomeDir + "/target/jmh-results/" + logFileRoot + ".csv")
                .addProfiler(StackProfiler.class)
                .addProfiler(GCProfiler.class)
                .addProfiler(ClassloaderProfiler.class)
                .addProfiler(CompilerProfiler.class)
                .jvmArgs(
                "-Xms1G",
                "-Xmx1G",
                "--patch-module",
                "openjceplus=" + projectHomeDir + "/target/classes",
                "--add-exports=java.base/sun.security.util=ALL-UNNAMED",
                "-Dock.library.path=/Users/jasonkatonica/Data/Libraries/gskit/8.9.6/OCK/jgsk_crypto",
                "-Djgskit.library.path=" + projectHomeDir + "/target/jgskit-aarch64-mac/")
                .forks(1)
                .output(projectHomeDir + "/target/jmh-results/"+ logFileRoot + ".txt")
                .build();
        
        //Add these conditionally based on os and arch:
        //.addProfiler(LinuxPerfProfiler.class)
        //.addProfiler(LinuxPerfNormProfiler.class)
        //.addProfiler(LinuxPerfAsmProfiler.class)
        //.addProfiler(WinPerfAsmProfiler.class)
        //.addProfiler(DTraceAsmProfiler.class)
        return opt;
    }

    protected void insertProvider(String provider) throws Exception {
        if (provider.equalsIgnoreCase("OpenJCEPlus")) {
            Provider myProvider = java.security.Security.getProvider("OpenJCEPlus");
            if (myProvider == null) {
                myProvider = (Provider) Class.forName("com.ibm.crypto.plus.provider.OpenJCEPlus")
                        .getDeclaredConstructor().newInstance();
            }
            java.security.Security.insertProviderAt(myProvider, 1);
        } else if (provider.equalsIgnoreCase("BC")) {
            Provider myProvider = java.security.Security.getProvider("BC");
            if (myProvider == null) {
                myProvider = (Provider) Class
                        .forName("org.bouncycastle.jce.provider.BouncyCastleProvider")
                        .getDeclaredConstructor().newInstance();
            }
            java.security.Security.insertProviderAt(myProvider, 1);
        }
    }
}
