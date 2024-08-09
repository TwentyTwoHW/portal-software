{
  pkgs,
  craneLib,
  rustToolchain,
  production ? true
}:

let
  linkerScriptFilter = path: builtins.match ".*memory.x$" path != null;
  linkerOrCargo = path: type:
    (linkerScriptFilter path) || (craneLib.filterCargoSources path type);
  src = pkgs.lib.cleanSourceWith {
    src = craneLib.path ../.;
    filter = linkerOrCargo;
  };
  vname = if production then "production" else "development";
  features = if production then "production" else "";

  commonArgs =  {
    pname = "firmware-${vname}";

    inherit src;

    doCheck = false;

    nativeBuildInputs = [
      pkgs.git
      pkgs.cmake
      pkgs.gcc-arm-embedded
      pkgs.clang
      pkgs.lld
    ];

    cargoVendorDir = craneLib.vendorMultipleCargoDeps {
      inherit (craneLib.findCargoFiles src) cargoConfigs;
      cargoLockList = [
        ./Cargo.lock
        "${rustToolchain.passthru.availableComponents.rust-src}/lib/rustlib/src/rust/Cargo.lock"
      ];
    };

    cargoLock = ./Cargo.lock;
    cargoToml = ./Cargo.toml;
    postUnpack = ''
      cd $sourceRoot/firmware
      sourceRoot="."
    '';
    # strictDeps = true;

    cargoExtraArgs = "-Z build-std=std,panic_abort -Z build-std-features=panic_immediate_abort --target thumbv7em-none-eabihf --no-default-features --features=${features} -v";
    CC_thumbv7em_none_eabihf = "clang-18";
    CFLAGS_thumbv7em_none_eabihf = "-flto -fno-data-sections -fno-function-sections -fno-PIC -fno-stack-protector --target=thumbv7em-none-eabihf -mcpu=cortex-m4 -mthumb -I${pkgs.clang_18}/resource-root/include/ -I${pkgs.gcc-arm-embedded}/arm-none-eabi/include";
  };
  
  # Don't actually build the dummy lib beacuse we can't link without a custom linker script
  cargoArtifacts = craneLib.buildDepsOnly (commonArgs // { cargoBuildCommand = "cargoWithProfile check"; });
in
craneLib.buildPackage (commonArgs // {
  pname = "portal-firmware-${vname}";

  inherit cargoArtifacts;

  # Nix please don't touch our binaries, thanks
  fixupPhase = "true";

  postInstall = ''
    mv $out/bin/firmware $out/firmware.elf
    ${pkgs.gcc-arm-embedded}/bin/arm-none-eabi-objcopy -O binary $out/firmware.elf $out/firmware.bin
    rm -rf $out/bin
  '';
  
  meta = with pkgs.lib; {
    description = "Firmware of the Portal hardware wallet";
    homepage = "https://github.com/TwentyTwoHW/portal-software.git";
    license = licenses.gpl3Plus;
    maintainers = [];
  };
})