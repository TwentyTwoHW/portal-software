{ pkgs, packages, devShells, getRust }:

let
  shell = devShells.embedded;
in
pkgs.dockerTools.buildNixShellImage {
  name = "portal-dev-environment";
  tag = "latest";
  homeDirectory = "/app";
  drv = shell;
}
