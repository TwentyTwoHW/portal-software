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

use proc_macro::TokenStream;

use quote::quote;

use syn::parse::{Parse, ParseStream};
use syn::punctuated::Punctuated;
use syn::{parse_macro_input, Ident, ItemFn, LitStr, Token};

#[derive(Debug, Clone, Default)]
struct Attributes {
    flash_file: Option<String>,
    entropy: Option<String>,
}

struct SingleAttr {
    name: Ident,
    _equal: Token![=],
    value: LitStr,
}

impl Parse for SingleAttr {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        Ok(SingleAttr {
            name: input.parse()?,
            _equal: input.parse()?,
            value: input.parse()?,
        })
    }
}

impl Parse for Attributes {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let mut attrs = Attributes::default();
        let parsed = Punctuated::<SingleAttr, Token![,]>::parse_terminated(input).unwrap();
        for attr in &parsed {
            match attr.name.to_string().as_str() {
                "flash_file" => attrs.flash_file = Some(attr.value.value()),
                "entropy" => attrs.entropy = Some(attr.value.value()),
                x => panic!("Invalid attr {}", x),
            }
        }

        Ok(attrs)
    }
}

#[proc_macro_attribute]
pub fn functional_test(attr: TokenStream, item: TokenStream) -> TokenStream {
    let attrs = parse_macro_input!(attr as Attributes);

    let mut input = parse_macro_input!(item as ItemFn);
    let original_ident = input.sig.ident.clone();
    let new_ident = Ident::new(&format!("{}_inner", original_ident), original_ident.span());
    input.sig.ident = new_ident.clone();

    let original_ident_str = original_ident.to_string();

    let flash = match attrs.flash_file {
        None => quote! { None },
        Some(path) => quote! {{
            Some((#path.into(), false))
        }},
    };
    let entropy = match attrs.entropy {
        None => quote! { None },
        Some(v) => quote! {{
            use std::str::FromStr;
            let entropy = #v.parse::<u64>().expect("Valid u64 number");
            Some(entropy)
        }},
    };

    let expanded = quote! {
        #[tokio::test(flavor ="multi_thread", worker_threads = 1)]
        async fn #original_ident() -> Result<(), crate::Error> {
            use std::io::Cursor;

            use tokio::sync::mpsc;

            #input

            crate::tests::INIT_LOG.call_once(|| {
                env_logger::init();
            });

            let (op_sender, op_receiver) = mpsc::channel(16);
            let (res_sender, res_receiver) = mpsc::channel::<Result<(), AssertionResult>>(16);

            let firmware = get_fw_path();
            let entropy = #entropy;
            let entropy = crate::utils::model::get_entropy(&entropy);

            let mut emulator = EmulatorInstance::spawn_qemu(
                &firmware,
                true,
                1,
                false,
                None,
                false,
                #flash,
                entropy,
            )
            .await?;

            let mut tester = Tester::new(op_sender, res_receiver);
            let handle = tokio::spawn(async move {
                tester.wait_ticks(4).await.expect("Tester is alive");
                let _ = #new_ident(tester).await;
            });

            let log = run_script(op_receiver, res_sender, &mut emulator).await?;
            if !log.result {
                let temp_dir = crate::tests::get_temp_dir();
                let to = temp_dir.join(concat!(#original_ident_str, ".html"));

                for TestLogStep { op, pass, .. } in &log.steps {
                    if !pass {
                        crate::utils::report::render_report(&to, &log)?;
                        assert!(false, "Test '{}' failed at {:?}. Report available here: {}", #original_ident_str, op, to.display());
                    }
                }
            }

            Ok(())
        }
    };

    TokenStream::from(expanded)
}
