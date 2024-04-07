const fn parse_int(s: &str) -> u32 {
    let mut v = 0;
    let mut i = 0;
    loop {
        if i >= s.as_bytes().len() {
            break;
        }

        v *= 10;
        v += match s.as_bytes()[i] {
            b'0' => 0,
            b'1' => 1,
            b'2' => 2,
            b'3' => 3,
            b'4' => 4,
            b'5' => 5,
            b'6' => 6,
            b'7' => 7,
            b'8' => 8,
            b'9' => 9,
            _ => panic!("Invalid digit"),
        };

        i += 1;
    }

    v
}

const fn get_current_version() -> u32 {
    let major = parse_int(env!("CARGO_PKG_VERSION_MAJOR"));
    let minor = parse_int(env!("CARGO_PKG_VERSION_MINOR"));
    let patch = parse_int(env!("CARGO_PKG_VERSION_PATCH"));

    major * 10000 + minor * 100 + patch
}

pub const CURRENT_VERSION: u32 = get_current_version();
pub const CURRENT_VARIANT: u8 = 0x00;

pub const TAIL_SIZE: usize = 5;

#[derive(Debug)]
pub struct UpdateTail {
    pub version: u32,
    pub variant: u8,
}

impl UpdateTail {
    pub fn parse(data: &[u8]) -> Self {
        if data.len() < TAIL_SIZE {
            panic!("Invalid tail");
        }

        UpdateTail {
            version: u32::from_be_bytes(data[..4].try_into().unwrap()),
            variant: data[4],
        }
    }
}
