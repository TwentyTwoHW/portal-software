{
    pkgs,
    craneLib
}:

craneLib.buildPackage {
  pname = "portal-sdk";
  version = (craneLib.crateNameFromCargoToml { cargoToml = ./Cargo.toml; }).version;

  src = craneLib.cleanCargoSource (craneLib.path ../.);
  strictDeps = true;

  cargoExtraArgs = "-p sdk";
  
  meta = with pkgs.lib; {
    description = "Portal SDK";
    homepage = "https://github.com/TwentyTwoHW/portal-software.git";
    license = licenses.gpl3Plus;
    maintainers = [];
  };
}