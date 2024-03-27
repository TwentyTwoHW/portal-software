{
    pkgs,
    craneLib
}:

let
  customFilter = path: builtins.match ".*\.(fl|hb)$" path != null;
  customFilterOrCargo = path: type:
    (customFilter path) || (craneLib.filterCargoSources path type);
  src = pkgs.lib.cleanSourceWith {
    src = craneLib.path ../.;
    filter = customFilterOrCargo;
  };
in
craneLib.buildPackage {
  pname = "portal-emulator";
  version = (craneLib.crateNameFromCargoToml { cargoToml = ./Cargo.toml; }).version;

  nativeBuildInputs = [
    pkgs.git
    pkgs.cmake
    pkgs.pkg-config
  ];

  buildInputs = [
    pkgs.fltk
    pkgs.pango
  ];

  inherit src;
  strictDeps = true;

  cargoExtraArgs = "-p emulator --bin gui";
  
  doCheck = false; # Emulator tests require the firmware to be available

  meta = with pkgs.lib; {
    description = "Emulator of the Portal hardware wallet";
    homepage = "https://github.com/TwentyTwoHW/portal-software.git";
    license = licenses.gpl3Plus;
    maintainers = [];
  };
}