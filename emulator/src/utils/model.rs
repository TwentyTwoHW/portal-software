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

use core::fmt;

use serde::{Deserialize, Serialize};

use embedded_graphics::pixelcolor::Gray8;
use embedded_graphics_simulator::OutputImage;

pub fn get_entropy(arg: &Option<u64>) -> u64 {
    use rand::RngCore;

    match arg {
        Some(ref val) => *val,
        None => rand::thread_rng().next_u64(),
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TestScript {
    pub sequence: Vec<TestOp>,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum TestOp {
    Action(TestAction),
    Assertion(TestAssertion),
}

impl From<TestAction> for TestOp {
    fn from(value: TestAction) -> Self {
        TestOp::Action(value)
    }
}
impl From<TestAssertion> for TestOp {
    fn from(value: TestAssertion) -> Self {
        TestOp::Assertion(value)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum NfcAction {
    GetStatus,
    SignPsbt(String),
    GenerateMnemonic(
        model::NumWordsMnemonic,
        model::bitcoin::Network,
        Option<String>,
    ),
    RestoreMnemonic(String, model::bitcoin::Network, Option<String>),
    RequestDescriptors,
    DisplayAddress(u32),
    Unlock(String),
    Resume,
    GetXpub(String),
    SetDescriptor(String, Option<model::BsmsRound2>),

    Raw(Vec<u8>),
}

#[derive(Debug, Deserialize, Serialize)]
pub enum TestAction {
    Nfc(NfcAction),
    Input(bool),
    WaitTicks(usize),
    Reset(bool),
}

#[derive(Debug, Deserialize, Serialize)]
pub enum TestAssertion {
    NfcResponse(model::Reply, bool),
    Display {
        content: String,
        timeout_updates: Option<usize>,
    },
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub enum AssertionResult {
    WrongDisplay(String),
    WrongReply(String),
    NoReply,
}
impl fmt::Display for AssertionResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self, f)
    }
}
impl std::error::Error for AssertionResult {}

#[derive(Debug)]
pub struct TestLogStep {
    pub op: TestOp,
    pub display: OutputImage<Gray8>,
    pub pass: bool,
    pub fail: Option<AssertionResult>,
    pub log_lines: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct TestLog {
    pub result: bool, // used in the Handlebars template
    pub steps: Vec<TestLogStep>,
}

impl Serialize for TestLogStep {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;

        let mut map = serializer.serialize_map(None)?;
        match &self.op {
            TestOp::Assertion(a) => {
                map.serialize_entry("is_assertion", &true)?;
                map.serialize_entry("assertion", &a)?;
                map.serialize_entry(
                    "assertion_json",
                    &serde_json::to_string(&a).expect("Valid assertion data"),
                )?;
            }
            TestOp::Action(a) => {
                map.serialize_entry("is_action", &true)?;
                map.serialize_entry("action", &serde_json::to_string(&a).expect("Valid action"))?;
            }
        }
        map.serialize_entry("display", &self.display.to_base64_png().expect("Valid PNG"))?;
        map.serialize_entry("pass", &self.pass)?;
        map.serialize_entry("fail", &self.fail)?;
        map.serialize_entry("print_log_lines", &!self.log_lines.is_empty())?;
        map.serialize_entry("log_lines", &self.log_lines)?;
        map.end()
    }
}
