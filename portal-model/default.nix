{
    pkgs,
    craneLib
}:

craneLib.buildPackage {
  pname = "portal-model";
  version = (craneLib.crateNameFromCargoToml { cargoToml = ./Cargo.toml; }).version;

  src = craneLib.cleanCargoSource (craneLib.path ../.);
  strictDeps = true;

  cargoExtraArgs = "-p portal-model";
  
  meta = with pkgs.lib; {
    description = "Model library for Portal software";
    homepage = "https://github.com/TwentyTwoHW/portal-software.git";
    license = licenses.gpl3Plus;
    maintainers = [];
  };
}