{ pkgs, packages }:

let
  qemuOnlyArm = packages.qemuPortal;
  firmwareOnly = pkgs.runCommand "pruneFirmwareDeps" {} ''
    mkdir -p $out/bin
    cp ${packages.firmware-development}/firmware.elf $out/bin/firmware
    ${pkgs.nukeReferences}/bin/nuke-refs $out/bin/firmware
  '';
  hostname = pkgs.writeShellScriptBin "hostname" ''
    echo "localhost";
  '';
  runVnc = pkgs.writeShellScriptBin "run-server" ''
    mkdir /tmp

    xvfb-run -l -n 22 -s "-screen 0 640x1280x24" emulator "$@" &

    export DISPLAY=:22
    x11vnc 2> /dev/null &

    echo "Click here to connect: http://localhost:2222/vnc.html?port=2222"
    echo "Alternatively you can also connect with a VNC client to: localhost:5900"

    exec novnc --listen 2222 2>/dev/null >/dev/null
  '';
  emulatorScript = pkgs.writeShellScriptBin "emulator" ''
    exec ${packages.emulator}/bin/gui --no-cargo-build --join-logs "$@"
  '';
in
pkgs.dockerTools.buildLayeredImage {
  name = "portal-emulator";
  tag = "latest";
  contents = pkgs.buildEnv {
    name = "image-root";
    paths = [ pkgs.bash emulatorScript runVnc hostname qemuOnlyArm firmwareOnly pkgs.gcc-arm-embedded pkgs.novnc pkgs.coreutils pkgs.xvfb-run pkgs.x11vnc pkgs.procps pkgs.gnugrep ];
    pathsToLink = [ "/bin" "/etc" "/var" ];
  };
  config = {
    Cmd = [ "run-server" "--firmware" "/bin/firmware" ];
    ExposedPorts = { "2222/tcp" = {}; "5900/tcp" = {}; };
  };
}
