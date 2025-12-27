// Portal Hardware Wallet firmware and supporting software libraries
//
// Copyright (C) 2024 Alekos Filini
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

use core::ops::Deref;

use alloc::{boxed::Box, vec::Vec};

use minicbor::{Decode, Encode};

use model::{ByteArray, EncryptionKey, SerializedDerivationPath};

use crate::hw::PAGE_SIZE;
use crate::{
    config::read_config,
    hw::{read_flash, write_flash, FlashError},
    CurrentState,
};

const CHECKPOINT_PAGE: usize = 254;

pub const MAGIC: u32 = 0xFA57B007;

pub const MAGIC_REGISTER: usize = 0;
const FIRST_KEY_REGISTER: usize = 1;
const FIRST_DATA_REGISTER: usize = 9;

#[derive(Debug, Encode, Decode)]
pub enum CheckpointVariant {
    #[cbor(n(0))]
    GenerateMnemonic,
    #[cbor(n(1))]
    UpdateFirmware {
        #[cbor(n(0))]
        state: FwUpdateState,
    },
    #[cbor(n(2))]
    SignPsbt,
    #[cbor(n(3))]
    SetDescriptor,
    #[cbor(n(4))]
    DisplayAddress(#[cbor(n(0))] u32),
    #[cbor(n(5))]
    GetXpub,
    #[cbor(n(6))]
    PublicDescriptor,

    #[cbor(n(7))]
    Removed,

    #[cbor(n(8))]
    ShowMnemonic {
        #[cbor(n(0))]
        is_backup: bool,
    },
}

impl CheckpointVariant {
    pub fn has_aux(&self) -> bool {
        match self {
            CheckpointVariant::UpdateFirmware { .. } => true,
            CheckpointVariant::GenerateMnemonic => false,
            CheckpointVariant::SignPsbt => true,
            CheckpointVariant::SetDescriptor => true,
            CheckpointVariant::DisplayAddress(_) => false,
            CheckpointVariant::GetXpub => true,
            CheckpointVariant::PublicDescriptor => false,
            CheckpointVariant::Removed => false,
            CheckpointVariant::ShowMnemonic { .. } => false,
        }
    }
}

#[derive(Debug, Encode, Decode, Clone, Copy)]
pub struct Resumable {
    #[cbor(n(0))]
    pub page: usize,
    #[cbor(n(1))]
    pub progress: u32,
    #[cbor(n(2))]
    pub ticks: usize,
}

impl Resumable {
    pub fn fresh() -> Self {
        Self::new_with_ticks(0, 0, 0)
    }

    pub fn new(page: usize, progress: u32) -> Self {
        Self::new_with_ticks(page, progress, 0)
    }

    pub fn new_with_ticks(page: usize, progress: u32, ticks: usize) -> Self {
        Resumable {
            page,
            progress,
            ticks,
        }
    }

    pub fn wrap_iter<'s, T>(
        &'s self,
        iter: impl Iterator<Item = T> + 's,
    ) -> impl Iterator<Item = (T, Self, bool)> + 's {
        self.wrap_iter_with_offset(0, iter)
    }

    pub fn wrap_iter_with_offset<'s, T>(
        &'s self,
        offset: usize,
        iter: impl Iterator<Item = T> + 's,
    ) -> impl Iterator<Item = (T, Self, bool)> + 's {
        iter.into_iter()
            .enumerate()
            .skip(self.page.saturating_sub(offset))
            .map(move |(page, v)| {
                let real_page = page + offset;
                let (state, draw) = if real_page == self.page {
                    (*self, self.ticks == 0)
                } else {
                    (Resumable::new(real_page, 0), true)
                };

                (v, state, draw)
            })
    }

    pub fn single_page_with_offset(&self, offset: usize) -> Option<(Self, bool)> {
        if self.page > offset {
            None
        } else if self.page == offset {
            Some((*self, self.ticks == 0))
        } else {
            Some((Resumable::new(offset, 0), true))
        }
    }
}

#[derive(Debug, Encode, Decode)]
pub struct Checkpoint {
    #[cbor(n(0))]
    pub variant: CheckpointVariant,
    #[cbor(n(1))]
    pub encryption_key: Box<ByteArray<24>>,
    #[cbor(n(2))]
    pub resumable: Option<Resumable>,
    #[cbor(skip)]
    pub aux: Option<Vec<u8>>,
}

impl Checkpoint {
    pub fn gen_key(rng: &mut impl rand::Rng) -> [u8; 24] {
        let mut encryption_key = [0; 24];
        rng.fill_bytes(&mut encryption_key);

        encryption_key
    }

    pub fn new_with_key(
        variant: CheckpointVariant,
        aux: Option<Vec<u8>>,
        resumable: Option<Resumable>,
        encryption_key: [u8; 24],
    ) -> Self {
        Checkpoint {
            variant,
            encryption_key: Box::new(encryption_key.into()),
            resumable,
            aux,
        }
    }

    pub fn new(
        variant: CheckpointVariant,
        aux: Option<Vec<u8>>,
        resumable: Option<Resumable>,
        rng: &mut impl rand::Rng,
    ) -> Self {
        Self::new_with_key(variant, aux, resumable, Self::gen_key(rng))
    }

    pub fn commit(
        &self,
        peripherals: &mut crate::handlers::HandlerPeripherals,
    ) -> Result<(), FlashError> {
        if self.variant.has_aux() && self.aux.is_none() {
            return Err(FlashError::CorruptedData);
        }

        self.commit_registers(&mut peripherals.rtc);
        if let Some(aux) = &self.aux {
            let mut key = EncryptionKey::new_stretch_key(self.encryption_key.deref().as_slice(), 0);
            let (aux, _) = key.encrypt(&aux).expect("Encryption workds");
            write_flash(&mut peripherals.flash, CHECKPOINT_PAGE, &aux)?;
        }

        Ok(())
    }

    pub fn commit_registers(&self, rtc: &crate::hw::Rtc) {
        for (v, reg) in self.serialize_registers().into_iter().enumerate() {
            rtc.write_backup_register(v + FIRST_DATA_REGISTER, reg);
        }
    }

    pub fn load(peripherals: &mut crate::handlers::HandlerPeripherals) -> Result<Self, FlashError> {
        let registers = (FIRST_DATA_REGISTER..31)
            .filter_map(|v| {
                let value = peripherals.rtc.read_backup_register(v);
                value.map(|v| v.to_be_bytes())
            })
            .flatten()
            .collect::<Vec<u8>>();
        let len = registers[0] as usize;
        if len > registers.len() - 1 {
            return Err(FlashError::CorruptedData);
        }
        let bytes = &registers[1..1 + len];

        let mut checkpoint: Self = minicbor::decode(&bytes)?;
        if checkpoint.variant.has_aux() {
            let mut buf = [0u8; PAGE_SIZE];
            let aux = read_flash(&mut peripherals.flash, CHECKPOINT_PAGE, &mut buf)?;

            let key =
                EncryptionKey::new_stretch_key(checkpoint.encryption_key.deref().as_slice(), 1);
            let aux = key
                .decrypt_raw(&aux)
                .map_err(|_| FlashError::CorruptedData)?;
            checkpoint.aux = Some(aux);
        }

        Ok(checkpoint)
    }

    fn serialize_registers(&self) -> alloc::vec::Vec<u32> {
        let bytes = minicbor::to_vec(&self).expect("Always succeeds");
        let len = bytes.len() as u8;
        let mut data = alloc::vec![len];
        data.extend(bytes);

        data.chunks(4)
            .map(|v| {
                if v.len() == 4 {
                    u32::from_be_bytes(v.try_into().unwrap())
                } else {
                    (*v.get(0).unwrap_or(&0) as u32) << 24
                        | (*v.get(1).unwrap_or(&0) as u32) << 16
                        | (*v.get(2).unwrap_or(&0) as u32) << 8
                }
            })
            .collect()
    }

    pub fn remove(self, rtc: &crate::hw::Rtc) {
        let removed = Self::new_with_key(CheckpointVariant::Removed, None, None, [0; 24]);
        removed.commit_registers(rtc);
    }

    pub fn into_current_state(
        self,
        peripherals: &mut crate::handlers::HandlerPeripherals,
    ) -> Result<CurrentState, FlashError> {
        use crate::handlers::init::TryIntoCurrentState;

        fn get_config(
            peripherals: &mut crate::HandlerPeripherals,
        ) -> Result<Option<CurrentState>, FlashError> {
            let config = read_config(&mut peripherals.flash)?;
            Ok(config.try_into_current_state(&peripherals.rtc).ok())
        }

        match (self.variant, self.aux, self.resumable) {
            (CheckpointVariant::UpdateFirmware { state }, Some(aux), _) => {
                let header = minicbor::decode(&aux)?;
                Ok(CurrentState::UpdatingFw {
                    header,
                    fast_boot: Some((state, (*self.encryption_key).into())),
                })
            }
            (CheckpointVariant::GenerateMnemonic, _, _) => {
                let config = read_config(&mut peripherals.flash)?;
                match config {
                    model::Config::Unverified(unverified) => {
                        Ok(CurrentState::UnverifiedConfig { config: unverified })
                    }
                    _ => Err(FlashError::CorruptedData),
                }
            }
            (CheckpointVariant::SignPsbt, Some(aux), Some(resumable)) => {
                if let Some(CurrentState::Idle { wallet }) = get_config(peripherals)? {
                    let aux: SignPsbtState = minicbor::decode(&aux)?;
                    Ok(CurrentState::ConfirmSignPsbt {
                        wallet,
                        resumable,
                        sig_bytes: aux.sig_bytes.into(),
                        encryption_key: (*self.encryption_key).into(),
                        fees: aux.fees,
                        outputs: aux.outputs,
                    })
                } else {
                    Err(FlashError::CorruptedData)
                }
            }
            (CheckpointVariant::SetDescriptor, Some(aux), Some(resumable)) => {
                if let Some(CurrentState::Idle { wallet }) = get_config(peripherals)? {
                    let aux: SetDescriptorState = minicbor::decode(&aux)?;
                    Ok(CurrentState::SetDescriptor {
                        wallet,
                        variant: aux.variant,
                        script_type: aux.script_type,
                        bsms: aux.bsms,
                        resumable,
                        is_fast_boot: true,
                        encryption_key: (*self.encryption_key).into(),
                    })
                } else {
                    Err(FlashError::CorruptedData)
                }
            }
            (CheckpointVariant::DisplayAddress(index), _, Some(resumable)) => {
                if let Some(CurrentState::Idle { wallet }) = get_config(peripherals)? {
                    Ok(CurrentState::DisplayAddress {
                        wallet,
                        index,
                        resumable,
                        is_fast_boot: true,
                    })
                } else {
                    Err(FlashError::CorruptedData)
                }
            }
            (CheckpointVariant::GetXpub, Some(aux), Some(resumable)) => {
                if let Some(CurrentState::Idle { wallet }) = get_config(peripherals)? {
                    let derivation_path: SerializedDerivationPath = minicbor::decode(&aux)?;
                    Ok(CurrentState::GetXpub {
                        wallet,
                        derivation_path: derivation_path.into(),
                        resumable,
                        is_fast_boot: true,
                        encryption_key: (*self.encryption_key).into(),
                    })
                } else {
                    Err(FlashError::CorruptedData)
                }
            }
            (CheckpointVariant::PublicDescriptor, _, Some(resumable)) => {
                if let Some(CurrentState::Idle { wallet }) = get_config(peripherals)? {
                    Ok(CurrentState::PublicDescriptor {
                        wallet,
                        resumable,
                        is_fast_boot: true,
                    })
                } else {
                    Err(FlashError::CorruptedData)
                }
            }
            (CheckpointVariant::ShowMnemonic { .. }, _, Some(resumable)) => {
                if let Some(CurrentState::Idle { wallet }) = get_config(peripherals)? {
                    Ok(CurrentState::ShowMnemonic {
                        wallet,
                        resumable,
                        is_fast_boot: true,
                    })
                } else {
                    Err(FlashError::CorruptedData)
                }
            }

            _ => Err(FlashError::CorruptedData),
        }
    }
}

pub fn write_fastboot_key(key: &[u8; 32], rtc: &crate::hw::Rtc) {
    for (i, v) in key.chunks_exact(4).enumerate() {
        rtc.write_backup_register(
            i + FIRST_KEY_REGISTER,
            u32::from_be_bytes(v.try_into().unwrap()),
        );
    }
}

pub fn get_fastboot_key(rtc: &crate::hw::Rtc) -> [u8; 32] {
    (FIRST_KEY_REGISTER..)
        .take(8)
        .filter_map(|v| {
            let value = rtc.read_backup_register(v);
            value.map(|v| v.to_be_bytes())
        })
        .flatten()
        .collect::<Vec<u8>>()
        .try_into()
        .unwrap()
}

#[derive(Debug, minicbor::Encode, minicbor::Decode)]
pub struct FwUpdateState {
    #[cbor(n(0))]
    pub next_page: usize,
    #[cbor(n(1))]
    pub midstate: alloc::boxed::Box<model::ByteArray<32>>,
    #[cbor(n(2))]
    pub tail: [u8; crate::version::TAIL_SIZE],
}

#[derive(Debug, minicbor::Encode, minicbor::Decode)]
pub struct SetDescriptorState {
    #[cbor(n(0))]
    pub variant: model::SetDescriptorVariant,
    #[cbor(n(1))]
    pub script_type: model::ScriptType,
    #[cbor(n(2))]
    pub bsms: Option<model::BsmsRound2>,
}

#[derive(Debug, minicbor::Encode, minicbor::Decode)]
pub struct CborAddress(
    #[cbor(n(0))]
    #[cbor(with = "cbor_bitcoin_address")]
    pub bitcoin::Address,
);
impl From<bitcoin::Address> for CborAddress {
    fn from(value: bitcoin::Address) -> Self {
        CborAddress(value)
    }
}
impl Into<bitcoin::Address> for CborAddress {
    fn into(self) -> bitcoin::Address {
        self.0
    }
}
impl core::ops::Deref for CborAddress {
    type Target = bitcoin::Address;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, minicbor::Encode, minicbor::Decode)]
pub enum DisplayAddress {
    #[cbor(n(0))]
    Address(#[cbor(n(0))] CborAddress),
    #[cbor(n(1))]
    BIP353(#[cbor(n(0))] alloc::string::String),
}

#[derive(Debug, minicbor::Encode, minicbor::Decode)]
pub struct SignPsbtState {
    #[cbor(n(0))]
    pub outputs: alloc::vec::Vec<(DisplayAddress, u64)>,
    #[cbor(n(1))]
    pub fees: u64,
    #[cbor(n(2))]
    pub sig_bytes: model::ByteVec,
}

mod cbor_bitcoin_address {
    use core::str::FromStr;

    use minicbor::{Decoder, Encoder};

    pub(super) fn decode<'b, Ctx>(
        d: &mut Decoder<'b>,
        _ctx: &mut Ctx,
    ) -> Result<bitcoin::Address, minicbor::decode::Error> {
        let s = d.decode::<&'b str>()?;
        bitcoin::Address::from_str(s)
            .map(|v| v.assume_checked())
            .map_err(|_| minicbor::decode::Error::message("Invalid bitcoin network").into())
    }

    pub(super) fn encode<Ctx, W: minicbor::encode::Write>(
        v: &bitcoin::Address,
        e: &mut Encoder<W>,
        _ctx: &mut Ctx,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        use alloc::string::ToString;

        e.encode(v.to_string())?;
        Ok(())
    }
}
