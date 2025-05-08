/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

/*
 * Checks the checkboxes to figure out the platforms
 * selected to build OpenJCEPlus on.
 *
 * @return      The platforms to build OpenJCEPlus on
 */
def getPlatforms() {
    def platforms = []

    if (PPC64_AIX == "true") {
        platforms.add("ppc64_aix")
    }

    if (X86_64_LINUX == "true") {
        platforms.add("x86-64_linux")
    }

    if (PPC64LE_LINUX == "true") {
        platforms.add("ppc64le_linux")
    }

    if (S390X_LINUX == "true") {
        platforms.add("s390x_linux")
    }

    if (X86_64_WINDOWS == "true") {
        platforms.add("x86-64_windows")
    }

    if (AARCH64_MAC == "true") {
        platforms.add("aarch64_mac")
    }

    if (X86_64_MAC == "true") {
        platforms.add("x86-64_mac")
    }

    if (AARCH64_LINUX == "true") {
        platforms.add("aarch64_linux")
    }

    return platforms
}

def renameFilesInDirectory(String directory, String prefix) {
    def sourceDirectory = new File(directory)
    def files = sourceDirectory.listFiles().findAll { it.isFile() }
    files.each { file ->
        def originalName = file.getName()
        def newName = "${prefix}${originalName}"
        def newFile = new File(directory, newName)
        if (file.renameTo(newFile)) {
            echo "File renamed from ${originalName} to ${newName}"
        } else {
            echo "Failed to rename file from ${originalName} to ${newName}"
        }
    }
}