{
  pkgs,
  craneLib,
  variant ? "device",
}:

let
  linkerScriptFilter = path: builtins.match ".*memory.x$" path != null;
  linkerOrCargo = path: type:
    (linkerScriptFilter path) || (craneLib.filterCargoSources path type);
  src = pkgs.lib.cleanSourceWith {
    src = craneLib.path ../.;
    filter = linkerOrCargo;
  };

  commonArgs =  {
    pname = "firmware-${variant}";

    inherit src;

    doCheck = false;

    nativeBuildInputs = [
      pkgs.git
      pkgs.cmake
      pkgs.gcc-arm-embedded
    ];

    cargoLock = ./Cargo.lock;
    cargoToml = ./Cargo.toml;
    postUnpack = ''
      cd $sourceRoot/firmware
      sourceRoot="."
    '';
    strictDeps = true;

    cargoExtraArgs = "--target thumbv7em-none-eabihf --no-default-features --features=${variant}";
    CC_thumbv7em_none_eabihf = "arm-none-eabi-gcc";
  };
  
  # Don't actually build the dummy lib beacuse we can't link without a custom linker script
  cargoArtifacts = craneLib.buildDepsOnly (commonArgs // { cargoBuildCommand = "cargoWithProfile check"; });
in
craneLib.buildPackage (commonArgs // {
  pname = "portal-firmware-${variant}";

  inherit cargoArtifacts;
  
  meta = with pkgs.lib; {
    description = "Firmware of the Portal hardware wallet";
    homepage = "https://github.com/TwentyTwoHW/portal-software.git";
    license = licenses.gpl3Plus;
    maintainers = [];
  };
})