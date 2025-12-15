# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

schema = 1
artifacts {
  zip = [
    "boundary_${version}_darwin_amd64.zip",
    "boundary_${version}_darwin_arm64.zip",
    "boundary_${version}_freebsd_386.zip",
    "boundary_${version}_freebsd_amd64.zip",
    "boundary_${version}_freebsd_arm.zip",
    "boundary_${version}_linux_386.zip",
    "boundary_${version}_linux_amd64.zip",
    "boundary_${version}_linux_arm.zip",
    "boundary_${version}_linux_arm64.zip",
    "boundary_${version}_netbsd_386.zip",
    "boundary_${version}_netbsd_amd64.zip",
    "boundary_${version}_netbsd_arm.zip",
    "boundary_${version}_openbsd_386.zip",
    "boundary_${version}_openbsd_amd64.zip",
    "boundary_${version}_openbsd_arm.zip",
    "boundary_${version}_solaris_amd64.zip",
    "boundary_${version}_windows_386.zip",
    "boundary_${version}_windows_amd64.zip",
  ]
  rpm = [
    "boundary-${version_linux}-1.aarch64.rpm",
    "boundary-${version_linux}-1.armv7hl.rpm",
    "boundary-${version_linux}-1.i386.rpm",
    "boundary-${version_linux}-1.x86_64.rpm",
  ]
  deb = [
    "boundary_${version_linux}-1_amd64.deb",
    "boundary_${version_linux}-1_arm64.deb",
    "boundary_${version_linux}-1_armhf.deb",
    "boundary_${version_linux}-1_i386.deb",
  ]
  container = [
    "boundary_default_linux_386_${version}_${commit_sha}.docker.dev.tar",
    "boundary_default_linux_386_${version}_${commit_sha}.docker.tar",
    "boundary_default_linux_amd64_${version}_${commit_sha}.docker.dev.tar",
    "boundary_default_linux_amd64_${version}_${commit_sha}.docker.tar",
    "boundary_default_linux_arm64_${version}_${commit_sha}.docker.dev.tar",
    "boundary_default_linux_arm64_${version}_${commit_sha}.docker.tar",
    "boundary_default_linux_arm_${version}_${commit_sha}.docker.dev.tar",
    "boundary_default_linux_arm_${version}_${commit_sha}.docker.tar",
  ]
}
