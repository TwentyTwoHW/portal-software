{
    pkgs,
    craneLib
}:

craneLib.buildPackage {
  pname = "portal-gui";
  version = (craneLib.crateNameFromCargoToml { cargoToml = ./Cargo.toml; }).version;

  nativeBuildInputs = [
    pkgs.git
    pkgs.cmake
    pkgs.pkg-config
  ];

  buildInputs = [
    pkgs.SDL2
  ];

  src = craneLib.cleanCargoSource (craneLib.path ../.);
  strictDeps = true;

  cargoExtraArgs = "-p gui --bin simulator --features=simulator";
  
  meta = with pkgs.lib; {
    description = "GUI simulator for Portal development";
    homepage = "https://github.com/TwentyTwoHW/portal-software.git";
    license = licenses.gpl3Plus;
    maintainers = [];
  };
}