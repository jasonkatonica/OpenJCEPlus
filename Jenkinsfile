/*
 * Copyright IBM Corp. 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

import groovy.json.JsonOutput;

// The Java version to be used.
def java_version = params.JAVA_VERSION
// The Java release to be used.
def java_release = params.JAVA_RELEASE
// The release of the OCK binaries to be used.
def ock_release = params.OCK_RELEASE

/*
 * Checks the checkboxes to figure out the platforms
 * selected to build OpenJCEPlus on.
 *
 * @return      The platforms to build OpenJCEPlus on
 */
def getPlatforms() {
    def platforms = []

    if (params.ppc64_aix == true) {
        platforms.add("ppc64_aix")
    }

    if (params.x86_64_linux == true) {
        platforms.add("x86-64_linux")
    }

    if (params.ppc64le_linux == true) {
        platforms.add("ppc64le_linux")
    }

    if (params.s390x_linux == true) {
        platforms.add("s390x_linux")
    }

    if (params.x86_64_windows == true) {
        platforms.add("x86-64_windows")
    }

    if (params.aarch64_mac == true) {
        platforms.add("aarch64_mac")
    }

    if (params.x86_64_mac == true) {
        platforms.add("x86-64_mac")
    }

    if (params.aarch64_linux == true) {
        platforms.add("aarch64_linux")
    }

    return platforms
}

/*
 * Checks whether OpenJCEPlus is buildable on this platform.
 *
 * @return  Whether OpenJCEPlus is buildable on the platform
 */
def isBuildable(hardware, software) {
    return ((software == "aix")
        || ((software == "linux") && ((hardware == "x86-64")
                                   || (hardware == "ppc64le")
                                   || (hardware == "s390x")
                                   || (hardware == "aarch64")))
        || ((software == "mac") && ((hardware == "aarch64")
                                 || (hardware == "x86-64")))
        || ((software == "windows") && (hardware == "x86-64")))

}

/*
 * Get the proper representation of the platform for OCK.
 *
 * @return  The proper representation of the platform for OCK
 */
def getOCKTarget(hardware, software) {
    def target = ""

    /*
     * Based on the specific hardware and software, pick the
     * appropriate option to use when getting OCK binaries to
     * set up the environment for the build.
     */
    if (software == "aix") {
        target = "aix64_ppc"
    } else if (software == "linux") {
        if (hardware == "x86-64") {
            target = "linux64_x86"
        } else if (hardware == "ppc64le") {
            target = "linux64_ppcle"
        } else if (hardware == "s390x") {
            target = "linux64_s390"
        } else if (hardware == "aarch64") {
            target = "linux64_arm"
        }
    } else if (software == "mac") {
        if (hardware == "aarch64") {
            target = "osx64_arm"
        } else if (hardware == "x86-64") {
            target = "osx64_x86"
        }
    } else if (software == "windows") {
        if (hardware == "x86-64") {
            target = "win64_x86"
        }
    }

    return target
}

/*
 * Figure out the proper URL, get the OCK binaries,
 * extract them and copy the files to the required
 * locations.
 */
def getBinaries(hardware, software) {
    if (ock_release == "") {
        ock_release = "20240521_8.9.6"
    }
    def target = getOCKTarget(hardware, software)
    def gskit_bin = "https://na.artifactory.swg-devops.com/artifactory/sec-gskit-javasec-generic-local/gskit8/$ock_release/$target/jgsk_crypto.tar"
    def gskit_sdk_bin = "https://na.artifactory.swg-devops.com/artifactory/sec-gskit-javasec-generic-local/gskit8/$ock_release/$target/jgsk_crypto_sdk.tar"
    
    // If user has specified OCK_FULL_URL, override default location.
    def ockUrl = params.OCK_FULL_URL
    if (ockUrl != "") {
        gskit_bin = "${ockUrl}/jgsk_crypto.tar"
        gskit_sdk_bin = "${ockUrl}/jgsk_crypto_sdk.tar"
    }
    dir("openjceplus/OCK") {
        withCredentials([usernamePassword(credentialsId: '7c1c2c28-650f-49e0-afd1-ca6b60479546', passwordVariable: 'GSKIT_PASSWORD', usernameVariable: 'GSKIT_USERNAME')]) {
            sh "curl -u $GSKIT_USERNAME:$GSKIT_PASSWORD $gskit_bin > jgsk_crypto.tar"
            sh "curl -u $GSKIT_USERNAME:$GSKIT_PASSWORD $gskit_sdk_bin > jgsk_crypto_sdk.tar"
        }
        untar file: 'jgsk_crypto.tar'
        untar file: 'jgsk_crypto_sdk.tar'

        if (target.contains('osx')) {
            fileOperations([fileCopyOperation(includes: 'libjgsk8iccs.dylib', targetLocation: 'jgsk_sdk/lib64')])
        } else if (target.contains('win')) {
            fileOperations([fileCopyOperation(includes: 'jgsk8iccs_64.dll', targetLocation: 'jgsk_sdk/lib64')])
        } else {
            fileOperations([fileCopyOperation(includes: 'libjgsk8iccs_64.so', targetLocation: 'jgsk_sdk/lib64')])
        }

        // Additional copy is required
        if (target.contains('aix')) {
            fileOperations([fileCopyOperation(includes: 'libjgsk8iccs_64.so', targetLocation: 'jgsk_sdk')])
        }
    }
}

/*
 * Figure out the proper URL, get the Semeru JDK,
 * extract it and rename the containing folder to
 * be used later on.
 */
def getJava(hardware, software) {
    def extension = "tar.gz"
    if (software == "windows") {
        extension = "zip"
    }

    if (hardware == "x86-64") {
        hardware = "x64"
    }

    def java_link = ""
    if (java_release == "") {
        java_link = "https://api.adoptopenjdk.net/v3/binary/latest/${java_version}/ga/${software}/${hardware}/jdk/openj9/normal/ibm?project=jdk"
    } else {
        def java_release_link = java_release.replace("+", "%2B")
        java_link = "https://api.adoptopenjdk.net/v3/binary/version/${java_release_link}/${software}/${hardware}/jdk/openj9/normal/ibm?project=jdk"
    }
    
    dir("java") {
        sh "curl -LJkO ${java_link}"
        def java_file = sh (
            script: 'ls | grep \'tar\\|zip\'',
            returnStdout: true
        ).trim()

        if (software == "windows") {
            unzip zipFile: "$java_file"
        } else {
            untar file: "$java_file"
        }
        sh "rm $java_file"

        def java_folder = sh (
            script: "ls | grep \'jdk-${java_version}\'",
            returnStdout: true
        ).trim()
        fileOperations([folderRenameOperation(destination: 'jdk', source: "$java_folder")])
    }
}

/*
 * Get the Maven tool and extract it.
 */
def getMaven() {
    sh "curl -kLO https://dlcdn.apache.org/maven/maven-3/3.9.6/binaries/apache-maven-3.9.6-bin.tar.gz"
    untar file: "apache-maven-3.9.6-bin.tar.gz"
}

/*
 * Clone the branch from the repo specified to
 * get the appropriate OpenJCEPlus code to build.
 */
def cloneOpenJCEPlus() {
    dir("openjceplus/OpenJCEPlus") {
        if ((params.OPENJCEPLUS_REPO == "") && (params.OPENJCEPLUS_BRANCH == "")) {
            echo "Clone using default branch and repository."
            checkout scm
        } else {
            echo "Clone using ${params.OPENJCEPLUS_BRANCH} from ${params.OPENJCEPLUS_REPO}"
            git branch: "${params.OPENJCEPLUS_BRANCH}", url: "${params.OPENJCEPLUS_REPO}"
        }
    }
}

/*
 * Get the appropriate test flag.
 *
 * The user might have requested that test are not
 * run or asked for a specific test to
 * be executed.
 *
 * Even if that's not the case, in some
 * platforms the OpenJCEPlusFIPS provider is not
 * available and thus the FIPS-related tests should
 * not be executed.
 */
def getTestFlag(hardware, software) {
    // User requested that tests not be executed.
    if (params.EXECUTE_TESTS == false) {
        return " -DskipTests"
    }

    // User requested execution of a specific test.
    def specificTest = params.SPECIFIC_TEST
    if (specificTest != "") {
        return " -Dtest=${specificTest}"
    }

    // Based on platform, decide whether FIPS tests should be run.
    if ((software == "mac") || ((software == "linux") && (hardware == "aarch64"))) {
        echo "Only non-FIPS tests can be run in ${hardware}_${software}"
        return " -Dtest=ibm.jceplus.junit.openjceplus.TestAll," +
                       "ibm.jceplus.junit.TestMemStressAll," +
                       "ibm.jceplus.junit.TestMultithread," +
                       "ibm.jceplus.junit.openjceplus.integration.TestAll"
    } else {
        echo "All tests (both FIPS and non-FIPS) can be run in ${hardware}_${software}"
        return "";
    }
}

/*
 * Export the appropriate environment variables
 * and run the requested maven commands.
 */
def runOpenJCEPlus(command, software) {
    dir("openjceplus/OpenJCEPlus") {
        def additional_exports = ""
        if (software == "aix") {
            additional_exports = "export LIBPATH=$WORKSPACE/openjceplus/OCK/:$WORKSPACE/openjceplus/OCK/jgsk_sdk;"
        }

        def additional_envars = params.ADDITIONAL_ENVARS
        if (additional_envars != "") {
            for (envar in additional_envars.split(",")) {
                additional_exports += " export ${envar.trim()};"
            }
            
        }

        def java_home = "export JAVA_HOME=$WORKSPACE/java/jdk;"
        def gskit_home = "export GSKIT_HOME=$WORKSPACE/openjceplus/OCK/jgsk_sdk;"
        def environment = "export PATH=$WORKSPACE/apache-maven-3.9.6/bin:\$PATH;"
        def ock_path = "$WORKSPACE/openjceplus/OCK/"
        if (software == "windows") {
            def workspace_unix_style = "$WORKSPACE".replace("\\", "/").replace("C:", "/cygdrive/c")
            environment = """export PATH=${workspace_unix_style}/apache-maven-3.9.6/bin:/cygdrive/c/Program\\ Files\\ \\(x86\\)/Windows\\ Kits/10/bin/10.0.19041.0/x64/:/cygdrive/c/Program\\ Files/Microsoft\\ Visual\\ Studio/2022/Professional/VC/Tools/MSVC/14.31.31103/bin/Hostx64/x64/:\$PATH;\\
                            |export INCLUDE="C:/Program Files (x86)/Windows Kits/10/include/10.0.19041.0/um/;C:/Program Files (x86)/Windows Kits/10/include/10.0.19041.0/shared/;C:/Program Files/Microsoft Visual Studio/2022/Professional/VC/Tools/MSVC/14.31.31103/include/;C:/Program Files (x86)/Windows Kits/10/include/10.0.19041.0/ucrt/";\\
                            |export LIB="C:/Program Files/Microsoft Visual Studio/2022/Professional/VC/Tools/MSVC/14.31.31103/lib/x64;C:/Program Files (x86)/Windows Kits/10/lib/10.0.19041.0/ucrt/x64;C:/Program Files (x86)/Windows Kits/10/lib/10.0.19041.0/um/x64";\\
                            |""".stripMargin()
            java_home = "export JAVA_HOME=\"$WORKSPACE\\java\\jdk\";"
            gskit_home = "export GSKIT_HOME=\"$WORKSPACE\\openjceplus\\OCK\\jgsk_sdk\";"
            ock_path = "$WORKSPACE\\openjceplus\\OCK\\"
        } else if (software == "mac") {
            java_home = "export JAVA_HOME=$WORKSPACE/java/jdk/Contents/Home;"
        }
        
        sh "${java_home} ${gskit_home} ${additional_exports} ${environment} mvn '-Dock.library.path=${ock_path}' --batch-mode ${command}"
        
    }
}

/*
 * Upload the compressed build into Artifactory.
 *
 * @param uploadSpec    This is the struct containing the upload specification
 * @return              The URL of the server used to upload
 */
def upload_artifactory(uploadSpec) {
    echo "Uploading to artifactory..."
    // Specify the Artifactory server to be used.
    def server = Artifactory.server 'na-public.artifactory.swg-devops'
    // Set connection timeout to 10 mins to avoid timeout on slow platforms.
    server.connection.timeout = 600

    // Create build info for this pipeline.
    def buildInfo = Artifactory.newBuildInfo()
    buildInfo.retention maxBuilds: 30, maxDays: 60, deleteBuildArtifacts: true
    buildInfo.env.capture = true
    buildInfo.name = "sys-rt/" + buildInfo.name

    // Upload to Artifactory and retry  if errors occur
    def ret = false
    retry(3) {
        if (ret) {
            sleep time: 300, unit: 'SECONDS'
        } else {
            ret = true
        }
        server.upload spec: uploadSpec, buildInfo: buildInfo
        server.publishBuildInfo buildInfo
    }

    return server.getUrl()
}

/* 
 * Returns a formatted directory name based upon a branch name.
 */
def getSanitizedBranchName() {
    SANITIZED_BRANCH_NAME=sh(
        script: "echo $env.GIT_BRANCH | tr -c '[:alpha:][:digit:][.]' '-' | tr -d '\r\n' | sed 's/.\$//'",
        returnStdout: true
    ).trim()
    return SANITIZED_BRANCH_NAME
}

/*
 * Creates the upload specification and triggers the process
 * of uploading the compressed file to Artifactory.
 *
 * @param platform      The platform for which OpenJCEPlus was built
 * @return              The URL to the uploaded file
 */
def archive(platform) {
    
    // Create compressed file containing build.
    def ending = ".tar.gz"
    def filename = "openjceplus-target-$platform$ending"
    dir("openjceplus/OpenJCEPlus/target") {
        tar archive: false, compress: true, defaultExcludes: false, dir: '', exclude: '', file: "$filename", glob: '', overwrite: false
    }

    // Set the specific specifications to upload build.
    def buildID = "${env.BUILD_ID}"
    def fileLocation = "$WORKSPACE/openjceplus/OpenJCEPlus/target"
    def sanitizedBranchName = getSanitizedBranchName()
    def directory = "sys-rt-generic-local/OpenJCEPlus_builds/$sanitizedBranchName/$buildID"

    // The OpenJCEPlus repo to be used
    def repo = "NULL"
    if (params.OPENJCEPLUS_REPO == "") {
        repo = env.GIT_URL
    } else {
        repo = params.OPENJCEPLUS_REPO
    }
    // The OpenJCEPlus branch to be used
    def branch = "NULL"
    if (params.OPENJCEPLUS_BRANCH == "") {
        branch = env.GIT_BRANCH
    } else {
        branch = params.OPENJCEPLUS_BRANCH
    }
    def specs = []
    def spec = ["pattern": "$fileLocation/$filename",
                "target": "$directory/$filename",
                "props": "java_release=$java_release;ock_release=$ock_release;repo=$repo;branch=$branch"]
    specs.add(spec)

    def uploadFiles = [files : specs]
    def uploadSpec = JsonOutput.toJson(uploadFiles)
    // Upload compressed build.
    def serverUrl = upload_artifactory(uploadSpec)
    def fileUrl = "$serverUrl/$directory/$filename"

    echo "Compressed and uploaded target for $branch of $repo: $fileUrl"

    // Add it to the description for quick access.
    currentBuild.description += "<br><a href=$fileUrl>$filename</a>"
}

/*
 * Figure out the appropriate node tags based on the platform and
 * execute the whole pipeline on a node that conforms to them.
 *
 * @param platform  The platform for which OpenJCEPlus will be built
 * @return          The node that will perform the build
 */
def run(platform) {
    def platformArray = platform.split("_")
    def hardware = platformArray[0]
    def software = platformArray[1]

    def isBuildable = isBuildable(hardware, software)
    if (!isBuildable) {
        return {
            echo "OpenJCEPlus is not supported on $hardware and $software"
        }
    }

    def node_hardware = hardware
    if (hardware.contains('x86')) {
        node_hardware = "x86"
    }

    def node_software = software
    if (software == "windows") {
        node_software = "windows.2022"
    }

    return {
        def excludeNode = []
        retry(3) {
            // Specific labels are selected based on platform.
            def nodeTags = "hw.arch.${node_hardware}&&sw.os.${node_software}"
            // Nodes where a failed attempt was made are excluded.
            excludeNode.each { nodeTags += "&&!" + it }

            // Some OSes have some further specific requirements.
            if (software == "aix") {
                // Timing issue with some machines.
                // TODO: Remove this when issue https://github.ibm.com/runtimes/infrastructure/issues/7198 is resolved.
                nodeTags += "&&!ci.role.build.release"
            }

            // Exclude machines that are FIPS140-2 configured.
            nodeTags += "&&!ci.role.test.fips"

            // Add additional labels specified by user.
            nodeTags += (params.ADDITIONAL_NODE_LABELS) ? "&&" + params.ADDITIONAL_NODE_LABELS : ""

            // Override labels as specified by user.
            nodeTags = (params.OVERRIDE_NODE_LABELS) ?: nodeTags

            echo "${nodeTags}"

            node("$nodeTags") {
                try {
                    getJava(hardware, software)
                    echo "Java fetched"
                    getBinaries(hardware, software)
                    echo "Binaries fetched"
                    getMaven()
                    echo "Maven fetched"
                    cloneOpenJCEPlus()
                    echo "OpenJCEPlus cloned"
                    def command = "install"
                    command += getTestFlag(hardware, software)
                    runOpenJCEPlus(command, software)
                    echo "OpenJCEPlus built"
                    archive(platform)
                    echo "OpenJCEPlus archived"
                } finally {
                    cleanWs()
                }
                
            }
        }
    }
}

/*
 * Allows the user to build and optionally test specific OpenJCEPlus repos and
 * branches in multiple platforms and Java versions. The OCK release or binary
 * used can be specified or default to the latest version.
 * After successful completion of the build, the result is compressed
 * and uploaded into Artifactory, for personal use or use by other pipelines.
 */
pipeline {
    parameters {
        separator(name: "TargetPlatforms", sectionHeader: "Target Platforms",
            separatorStyle: "border-width: 0",
            sectionHeaderStyle: """
                background-color: rgb(24, 42, 118);
                text-align: center;
                padding: 4px;
                color: rgb(255, 255, 255);
                font-size: 22px;
                font-weight: normal;
                text-transform: uppercase;
                font-family: 'Orienta', sans-serif;
                letter-spacing: 1px;
                font-style: italic;
            """
        )
        booleanParam(name: 'ppc64_aix', defaultValue: false, description: '\
            Build for ppc64_aix platform')
        booleanParam(name: 'x86_64_linux', defaultValue: true, description: '\
            Build for x86-64_linux platform')
        booleanParam(name: 'ppc64le_linux', defaultValue: true, description: '\
            Build for ppc64le_linux platform')
        booleanParam(name: 's390x_linux', defaultValue: true, description: '\
            Build for s390x_linux platform')
        booleanParam(name: 'x86_64_windows', defaultValue: true, description: '\
            Build for x86-64_windows platform')
        booleanParam(name: 'aarch64_mac', defaultValue: true, description: '\
            Build for aarch64_mac platform')
        booleanParam(name: 'x86_64_mac', defaultValue: true, description: '\
            Build for x86-64_mac platform')
        booleanParam(name: 'aarch64_linux', defaultValue: true, description: '\
            Build for aarch64_linux platform')
        separator(name: "BuildAndTestPlatforms", sectionHeader: "Build And Test Options",
            separatorStyle: "border-width: 0",
            sectionHeaderStyle: """
                background-color: rgb(24, 42, 118);
                text-align: center;
                padding: 4px;
                color: rgb(255, 255, 255);
                font-size: 22px;
                font-weight: normal;
                text-transform: uppercase;
                font-family: 'Orienta', sans-serif;
                letter-spacing: 1px;
                font-style: italic;
            """
        )
        string(name: 'OPENJCEPLUS_REPO', defaultValue: '', description: '\
            The OpenJCEPlus repo to be used. When not specified this will default to the repository scanned by this multibranch pipeline.\
            Typically this will use https://github.com/IBM/OpenJCEPlus')
        string(name: 'OPENJCEPLUS_BRANCH', defaultValue: '', description: '\
            The OpenJCEPlus branch to be used. When not specified this will default to the branch scanned by this multibranch pipeline.')
        choice(name: 'JAVA_VERSION', choices: ['23', '22', '21', '17', '11'], description: '\
            Specify the Java version your branch uses to build.')
        string(name: 'JAVA_RELEASE', defaultValue: '', description: '\
            Indicate a specific Java release that you want to use to build your branch.<br> \
            If left empty, the default release for the chosen version will be used.<br> \
            Specify the full name of the release.<br> \
            (i.e., jdk-&ltjdk version&gt_openj9-&ltopenj9 version&gt => eg., jdk-21.0.2+13_openj9-0.43.0)')
        string(name: 'OCK_RELEASE', defaultValue: '', description: '\
            Indicate the specific release of the OCK binaries that you want to use to build your branch.<br> \
            If left empty, the latest release will be used.<br> \
            Specify the full name of the release.<br> \
            (i.e., &ltrelease date(YYYYMMDD)&gt_&ltOCK version&gt => eg., 20230802_8.9.5) \
        ')
        string(name: 'OCK_FULL_URL', defaultValue: '', description: ' \
            This parameter can be used if one wants to specify the full URL from which to get OCK.<br> \
            BEWARE: This can only be used with a single platform and it overrides OCK_RELEASE. \
        ')
        separator(name: "TestOptions", sectionHeader: "Test Options",
            separatorStyle: "border-width: 0",
            sectionHeaderStyle: """
                background-color: rgb(24, 42, 118);
                text-align: center;
                padding: 4px;
                color: rgb(255, 255, 255);
                font-size: 22px;
                font-weight: normal;
                text-transform: uppercase;
                font-family: 'Orienta', sans-serif;
                letter-spacing: 1px;
                font-style: italic;
            """
        )
        booleanParam(name: 'EXECUTE_TESTS', defaultValue: true, description:'\
            Execute tests during the build')
        string(name: 'SPECIFIC_TEST', defaultValue: '', description: '\
            Set this to only execute a specific test, instead of the whole test suite.<br> \
            Keep in mind that EXECUTE_TESTS has to be set too for this to work.')
        string(name: 'PARALLEL_ITERATIONS', defaultValue: '', description: '\
            Number of iterations to run all stages for each of the specified platforms. The iterations will run in parallel.')
        separator(name: "ExtendedOptions", sectionHeader: "Extended Options",
            separatorStyle: "border-width: 0",
            sectionHeaderStyle: """
                background-color: rgb(24, 42, 118);
                text-align: center;
                padding: 4px;
                color: rgb(255, 255, 255);
                font-size: 22px;
                font-weight: normal;
                text-transform: uppercase;
                font-family: 'Orienta', sans-serif;
                letter-spacing: 1px;
                font-style: italic;
            """
        )
        string(name: 'ADDITIONAL_NODE_LABELS', defaultValue: '', description: '\
            Additional labels for the node to be used can be defined here.<br> \
            These labels will be added to the automatically generated ones, pertaining to platform specified.')
        string(name: 'OVERRIDE_NODE_LABELS', defaultValue: '', description: '\
            The labels specified will override any other labels chosen and will be the only ones utilized.')
        string(name: 'ADDITIONAL_ENVARS', defaultValue: '', description: '\
            Additional environment variables that one might want to add to the existing ones.<br> \
            Specify them in comma-separated pairs of name and value (e.g. ENVAR1=value1, ENVAR2=value2, ...).<br><br> \
            Beware of what you add as it might be overriding existing environment variables.<br> \
            NOTE: those will be added to all selected platforms.')
        string(name: 'TIMEOUT_TIME', defaultValue: '6', description: '\
            Overall build timeout (HOURS)')
    }

    agent any
    stages {
        stage('Build And Test OpenJCEPlus') {
            steps {
                timestamps {
                    script {
                        def timeoutTime = params.TIMEOUT_TIME
                        timeout(time: "${timeoutTime}".toInteger(), unit: 'HOURS') {
                            // Figure out the platforms to build on.
                            def platforms = getPlatforms()
                            assert !((platforms.size() > 1) && (params.OCK_FULL_URL != "")) : "Cannot specify full OCK URL and multiple platforms."

                            // Check whether the build has to be run multiple times in parallel.
                            def iter = (params.PARALLEL_ITERATIONS ?: "1").toInteger()
                            echo "Parallel iterations to be run: ${iter}"
                        
                            def mapForParallel = [:]
                            currentBuild.description = ""
                            // Create jobs for each platform, as provided by user.
                            for (i = 0; i < iter; i++) {
                                for (platform in platforms) {
                                    mapForParallel["${platform}: Iteration ${i}"] = run(platform.trim())
                                }
                            }
                            // Run said jobs in parallel.
                            parallel mapForParallel
                        }
                    }
                }
            }
        }
    }
}
