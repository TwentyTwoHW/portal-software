{ pkgs, packages, getRust }:

let
  qemuOnlyArm = packages.smallQemu;
  shell = pkgs.mkShell {
    buildInputs = with pkgs; [ cmake pkg-config qemuOnlyArm (getRust { withEmbedded = true; }) ];

    CC_thumbv7em_none_eabihf = "${pkgs.gcc-arm-embedded}/bin/arm-none-eabi-gcc";
  };
in
pkgs.dockerTools.buildNixShellImage {
  name = "portal-dev-environment";
  tag = "latest";
  homeDirectory = "/app";
  drv = shell;
}
