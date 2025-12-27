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

#![cfg_attr(feature = "stm32", no_std)]

extern crate alloc;

use embedded_graphics::draw_target::Clipped;
use embedded_graphics::mono_font::{ascii, MonoTextStyle};
use embedded_graphics::pixelcolor::BinaryColor::{self, *};
use embedded_graphics::prelude::*;
use embedded_graphics::primitives::{PrimitiveStyle, Rectangle};
use embedded_graphics::text::{Alignment, Baseline, Text, TextStyleBuilder};

use model::bitcoin::{Amount, Denomination};

const AMOUNT_Y_OFFSET: i32 = 6;

pub trait Page {
    fn draw_to<T>(&self, target: &mut T) -> Result<(), <T as DrawTarget>::Error>
    where
        T: DrawTarget<Color = BinaryColor> + Dimensions;

    fn init_display<T>(&self, target: &mut T) -> Result<(), <T as DrawTarget>::Error>
    where
        T: DrawTarget<Color = BinaryColor> + Dimensions,
    {
        self.reset(target)
    }

    fn reset<T>(&self, target: &mut T) -> Result<(), <T as DrawTarget>::Error>
    where
        T: DrawTarget<Color = BinaryColor> + Dimensions,
    {
        target
            .bounding_box()
            .into_styled(PrimitiveStyle::with_fill(Off))
            .draw(target)?;

        Ok(())
    }
}

#[derive(Debug)]
pub struct WelcomePage<'s> {
    version: &'s str,
}

impl<'s> WelcomePage<'s> {
    pub fn new(version: &'s str) -> Self {
        WelcomePage { version }
    }
}

impl<'s> Page for WelcomePage<'s> {
    fn draw_to<T>(&self, target: &mut T) -> Result<(), <T as DrawTarget>::Error>
    where
        T: DrawTarget<Color = BinaryColor>,
    {
        let screen_size = target.bounding_box();

        self.reset(target)?;

        Text::with_text_style(
            "Welcome",
            screen_size.center(),
            MonoTextStyle::new(&ascii::FONT_9X15_BOLD, On),
            TextStyleBuilder::new()
                .alignment(Alignment::Center)
                .baseline(Baseline::Bottom)
                .build(),
        )
        .draw(target)?;

        Text::with_text_style(
            "USE APP TO INITIALIZE",
            screen_size.center() + Point::new(0, 4),
            MonoTextStyle::new(&ascii::FONT_5X8, On),
            TextStyleBuilder::new()
                .alignment(Alignment::Center)
                .baseline(Baseline::Top)
                .build(),
        )
        .draw(target)?;

        Text::with_text_style(
            self.version,
            Point::new(127, 63),
            MonoTextStyle::new(&ascii::FONT_5X7, On),
            TextStyleBuilder::new()
                .alignment(Alignment::Right)
                .baseline(Baseline::Bottom)
                .build(),
        )
        .draw(target)?;

        Ok(())
    }
}

pub struct SingleLineTextPage<'s> {
    text: Text<'s, MonoTextStyle<'static, BinaryColor>>,
}

impl<'s> SingleLineTextPage<'s> {
    pub fn new(s: &'s str) -> Self {
        SingleLineTextPage {
            text: Text::with_text_style(
                s,
                Point::new(64, 32),
                MonoTextStyle::new(&ascii::FONT_8X13_BOLD, On),
                TextStyleBuilder::new()
                    .alignment(Alignment::Center)
                    .baseline(Baseline::Middle)
                    .build(),
            ),
        }
    }
}

impl<'s> Page for SingleLineTextPage<'s> {
    fn draw_to<T>(&self, target: &mut T) -> Result<(), <T as DrawTarget>::Error>
    where
        T: DrawTarget<Color = BinaryColor>,
    {
        self.text.draw(target)?;

        Ok(())
    }
}

macro_rules! impl_wrapper_page {
    ($struct:ident $(< $( $lifetimes:lifetime ),+ > )?, $inner:ty ) => {
        impl$( < $($lifetimes),* > )* Page for $struct $( < $($lifetimes),* > )*  {
            fn draw_to<T>(&self, target: &mut T) -> Result<(), <T as DrawTarget>::Error>
            where
                T: DrawTarget<Color = BinaryColor>,
            {
                self.0.draw_to(target)
            }
        }
        impl $( < $($lifetimes),* > )* core::ops::Deref for $struct $( < $($lifetimes),* > )* {
            type Target = $inner;

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }
        impl $( < $($lifetimes),* > )* core::ops::DerefMut for $struct $( < $($lifetimes),* > )* {
            fn deref_mut(&mut self) -> &mut Self::Target {
                &mut self.0
            }
        }
    }
}

pub struct InitialPage<'s> {
    welcome: Text<'s, MonoTextStyle<'static, BinaryColor>>,
    version: Text<'static, MonoTextStyle<'static, BinaryColor>>,
}

impl<'s> InitialPage<'s> {
    pub fn new(welcome: &'s str, version: &'static str) -> Self {
        InitialPage {
            welcome: Text::with_text_style(
                welcome,
                Point::new(64, 32),
                MonoTextStyle::new(&ascii::FONT_8X13_BOLD, On),
                TextStyleBuilder::new()
                    .alignment(Alignment::Center)
                    .baseline(Baseline::Middle)
                    .build(),
            ),
            version: Text::with_text_style(
                version,
                Point::new(127, 63),
                MonoTextStyle::new(&ascii::FONT_5X7, On),
                TextStyleBuilder::new()
                    .alignment(Alignment::Right)
                    .baseline(Baseline::Bottom)
                    .build(),
            ),
        }
    }
}

impl<'s> Page for InitialPage<'s> {
    fn draw_to<T>(&self, target: &mut T) -> Result<(), <T as DrawTarget>::Error>
    where
        T: DrawTarget<Color = BinaryColor>,
    {
        self.welcome.draw(target)?;
        self.version.draw(target)?;

        Ok(())
    }
}

pub struct LoadingPage(SingleLineTextPage<'static>);
impl_wrapper_page!(LoadingPage, SingleLineTextPage<'static>);
impl LoadingPage {
    pub fn new() -> Self {
        LoadingPage(SingleLineTextPage::new("LOADING"))
    }
}

pub struct SigningTxPage(SingleLineTextPage<'static>);
impl_wrapper_page!(SigningTxPage, SingleLineTextPage<'static>);
impl SigningTxPage {
    pub fn new() -> Self {
        SigningTxPage(SingleLineTextPage::new("Signing tx..."))
    }
}

pub trait MainContent {
    fn draw_to<T>(&self, target: &mut T) -> Result<(), <T as DrawTarget>::Error>
    where
        T: DrawTarget<Color = BinaryColor>;

    fn tick(&mut self) -> bool {
        false
    }
}

pub struct ConfirmBarPage<'s, C> {
    threshold: u32,
    confirmed: u32,
    main_content: C,
    idle_text: &'s str,
    holding_text: &'s str,
    bar_y: i32,
    invert: bool,
}

impl<'s, C> ConfirmBarPage<'s, C>
where
    C: MainContent,
{
    fn new_default_bar(
        threshold: u32,
        main_content: C,
        idle_text: &'s str,
        holding_text: &'s str,
    ) -> Self {
        Self::new(threshold, main_content, idle_text, holding_text, 44, false)
    }

    fn new(
        threshold: u32,
        main_content: C,
        idle_text: &'s str,
        holding_text: &'s str,
        bar_y: i32,
        invert: bool,
    ) -> Self {
        ConfirmBarPage {
            confirmed: 0,
            main_content,
            threshold,
            idle_text,
            holding_text,
            bar_y,
            invert,
        }
    }

    pub fn is_confirmed(&self) -> bool {
        self.confirmed > self.threshold
    }

    pub fn add_confirm(&mut self, value: u32) -> bool {
        self.confirmed += value;
        self.is_confirmed()
    }

    pub fn reset_confirm(&mut self) {
        self.confirmed = 0;
    }

    pub fn get_confirm(&self) -> u32 {
        self.confirmed
    }

    pub fn tick(&mut self) -> bool {
        self.main_content.tick()
    }
}

impl<'s, C> Page for ConfirmBarPage<'s, C>
where
    C: MainContent,
{
    fn draw_to<T>(&self, target: &mut T) -> Result<(), <T as DrawTarget>::Error>
    where
        T: DrawTarget<Color = BinaryColor>,
    {
        // self.reset(target)?;

        let screen_size = target.bounding_box();

        let main_bar_color = match self.invert {
            true => BinaryColor::Off,
            false => BinaryColor::On,
        };

        let x_coord = screen_size.size.width * self.confirmed / self.threshold;
        let x_size = screen_size.size.width.saturating_sub(x_coord);
        let bar = Rectangle::new(
            Point::new(x_coord as i32, self.bar_y),
            Size::new(x_size, 10),
        )
        .into_styled(PrimitiveStyle::with_fill(main_bar_color));

        let bg = Rectangle::new(
            Point::new(0, bar.primitive.top_left.y),
            Size::new(x_coord, bar.primitive.size.height),
        )
        .into_styled(PrimitiveStyle::with_fill(main_bar_color.invert()));

        bar.draw(target)?;
        bg.draw(target)?;

        fn draw_fn<X: DrawTarget<Color = BinaryColor>>(
            canvas: &mut Clipped<'_, X>,
            color: BinaryColor,
            text: &mut Text<'_, MonoTextStyle<BinaryColor>>,
        ) -> Result<(), <X as DrawTarget>::Error> {
            text.character_style.text_color = Some(color);
            text.draw(canvas)?;

            Ok(())
        }

        let text = match self.confirmed {
            ..=1 => self.idle_text,
            _ => self.holding_text,
        };
        let mut text_instance = Text::with_text_style(
            text,
            Point::new(
                (screen_size.size.width / 2) as i32,
                bar.primitive.top_left.y + 1,
            ),
            MonoTextStyle::new(&ascii::FONT_5X8, On),
            TextStyleBuilder::new()
                .alignment(Alignment::Center)
                .baseline(Baseline::Top)
                .build(),
        );
        draw_fn(
            &mut target.clipped(&bar.primitive),
            main_bar_color.invert(),
            &mut text_instance,
        )?;
        draw_fn(
            &mut target.clipped(&bg.primitive),
            main_bar_color,
            &mut text_instance,
        )?;

        self.main_content.draw_to(target)?;

        Ok(())
    }
}

pub struct EmptyContent;
impl MainContent for EmptyContent {
    fn draw_to<T>(&self, _: &mut T) -> Result<(), <T as DrawTarget>::Error>
    where
        T: DrawTarget<Color = BinaryColor>,
    {
        Ok(())
    }
}
pub struct FwUpdateProgressPage(ConfirmBarPage<'static, EmptyContent>);
impl_wrapper_page!(FwUpdateProgressPage, ConfirmBarPage<'static, EmptyContent>);
impl FwUpdateProgressPage {
    pub fn new(threshold: u32) -> Self {
        FwUpdateProgressPage(ConfirmBarPage::new(
            threshold,
            EmptyContent,
            "",
            "UPDATE IN PROGRESS",
            52,
            true,
        ))
    }
}

pub struct SummaryPageContent<'s>(&'s str);
impl<'s> MainContent for SummaryPageContent<'s> {
    fn draw_to<T>(&self, target: &mut T) -> Result<(), <T as DrawTarget>::Error>
    where
        T: DrawTarget<Color = BinaryColor>,
    {
        let font = MonoTextStyle::new(&ascii::FONT_9X15_BOLD, On);
        let y_coord = if self.0.contains('\n') {
            32 - AMOUNT_Y_OFFSET
        } else {
            32 + AMOUNT_Y_OFFSET
        };

        let text = Text::with_text_style(
            &self.0,
            Point::new(64, y_coord),
            font,
            TextStyleBuilder::new()
                .alignment(Alignment::Center)
                .baseline(Baseline::Bottom)
                .build(),
        );
        text.draw(target)?;

        Ok(())
    }
}
pub struct SummaryPage<'s>(ConfirmBarPage<'static, SummaryPageContent<'s>>);
impl_wrapper_page!(
    SummaryPage<'s>,
    ConfirmBarPage<'static, SummaryPageContent<'s>>
);
impl<'s> SummaryPage<'s> {
    pub fn new(summary: &'s str, idle_text: &'static str) -> Self {
        Self::new_with_threshold(summary, idle_text, 100)
    }

    pub fn new_with_threshold(summary: &'s str, idle_text: &'static str, threshold: u32) -> Self {
        SummaryPage(ConfirmBarPage::new_default_bar(
            threshold,
            SummaryPageContent(summary),
            idle_text,
            "KEEP HOLDING...",
        ))
    }
}

pub struct ScrollText<'s, const FACTOR: usize, const WAIT_TIME: usize, const MAX_CHARS: usize> {
    text: &'s str,
}

impl<'s, const FACTOR: usize, const WAIT_TIME: usize, const MAX_CHARS: usize>
    ScrollText<'s, FACTOR, WAIT_TIME, MAX_CHARS>
{
    fn new(text: &'s str) -> Self {
        ScrollText { text }
    }

    fn compute(&self, iteration: usize) -> &'s str {
        let max_start = self.text.len().saturating_sub(MAX_CHARS);
        let start = match (iteration / FACTOR) % (max_start * 2 + WAIT_TIME * 2) {
            v if v <= WAIT_TIME => 0,
            v if v <= max_start + WAIT_TIME => v - WAIT_TIME,
            v if v <= max_start + WAIT_TIME * 2 => max_start,
            v => 2 * max_start - (v - 2 * WAIT_TIME),
        };
        &self.text[start..start + core::cmp::min(MAX_CHARS, self.text.len())]
    }
}

pub struct TxOutputPageContent<'s> {
    address: &'s str,
    value: Amount,
    iteration: usize,
}

impl<'s> MainContent for TxOutputPageContent<'s> {
    fn draw_to<T>(&self, target: &mut T) -> Result<(), <T as DrawTarget>::Error>
    where
        T: DrawTarget<Color = BinaryColor>,
    {
        use alloc::string::*;

        let screen_size = target.bounding_box();
        let rectangle = Rectangle::new(Point::new(0, 2), Size::new(screen_size.size.width, 25))
            .into_styled(PrimitiveStyle::with_fill(Off));
        rectangle.draw(target)?;

        let address = self.address.to_string();
        let scroll = ScrollText::<1, 5, 15>::new(&address);

        let address_text = Text::with_text_style(
            scroll.compute(self.iteration),
            Point::new(64, 2),
            MonoTextStyle::new(&ascii::FONT_8X13_BOLD, On),
            TextStyleBuilder::new()
                .alignment(Alignment::Center)
                .baseline(Baseline::Top)
                .build(),
        );
        address_text.draw(target)?;

        let address_summary =
            alloc::format!("{:.8} ... {:.8}", &address, &address[address.len() - 8..]);
        let address_summary = Text::with_text_style(
            &address_summary,
            Point::new(64, 17),
            MonoTextStyle::new(&ascii::FONT_5X8, On),
            TextStyleBuilder::new()
                .alignment(Alignment::Center)
                .baseline(Baseline::Top)
                .build(),
        );
        address_summary.draw(target)?;

        let value = alloc::format!("{:.8} BTC", self.value.display_in(Denomination::Bitcoin));
        let scroll = ScrollText::<1, 5, 15>::new(&value);
        let value_text = Text::with_text_style(
            &scroll.compute(self.iteration),
            Point::new(64, 46),
            MonoTextStyle::new(&ascii::FONT_8X13_BOLD, On),
            TextStyleBuilder::new()
                .alignment(Alignment::Center)
                .baseline(Baseline::Bottom)
                .build(),
        );
        value_text.draw(target)?;

        Ok(())
    }

    fn tick(&mut self) -> bool {
        self.iteration += 1;
        true
    }
}
pub struct TxOutputPage<'s>(ConfirmBarPage<'static, TxOutputPageContent<'s>>);
impl_wrapper_page!(
    TxOutputPage<'s>,
    ConfirmBarPage<'static, TxOutputPageContent<'s>>
);
impl<'s> TxOutputPage<'s> {
    pub fn new(address: &'s str, value: Amount) -> Self {
        TxOutputPage(ConfirmBarPage::new(
            50,
            TxOutputPageContent {
                address,
                value,
                iteration: 0,
            },
            "HOLD BTN TO CONTINUE",
            "KEEP HOLDING...",
            52,
            false,
        ))
    }

    pub fn next(&mut self) {
        self.0.main_content.iteration += 1;
    }
}

pub struct TwoLinesText<'s, 'l> {
    small: &'s str,
    large: &'l str,
}

impl<'s, 'l> TwoLinesText<'s, 'l> {
    pub fn new(small: &'s str, large: &'l str) -> Self {
        TwoLinesText { small, large }
    }
}

impl<'s, 'l> MainContent for TwoLinesText<'s, 'l> {
    fn draw_to<T>(&self, target: &mut T) -> Result<(), <T as DrawTarget>::Error>
    where
        T: DrawTarget<Color = BinaryColor>,
    {
        let offset = if self.large.contains("\n") { 6 } else { 0 };

        let value_text = Text::with_text_style(
            self.small,
            Point::new(64, 10 - offset),
            MonoTextStyle::new(&ascii::FONT_6X10, On),
            TextStyleBuilder::new()
                .alignment(Alignment::Center)
                .baseline(Baseline::Top)
                .build(),
        );
        value_text.draw(target)?;

        let fees_text = Text::with_text_style(
            self.large,
            Point::new(64, 34 - offset),
            MonoTextStyle::new(&ascii::FONT_8X13_BOLD, On),
            TextStyleBuilder::new()
                .alignment(Alignment::Center)
                .baseline(Baseline::Bottom)
                .build(),
        );
        fees_text.draw(target)?;

        Ok(())
    }
}

pub struct ConfirmPairCodePage<'s>(ConfirmBarPage<'static, TwoLinesText<'static, 's>>);
impl_wrapper_page!(
    ConfirmPairCodePage<'s>,
    ConfirmBarPage<'static, TwoLinesText<'static, 's>>
);
impl<'s> ConfirmPairCodePage<'s> {
    pub fn new(pair_code: &'s str) -> Self {
        ConfirmPairCodePage(ConfirmBarPage::new_default_bar(
            100,
            TwoLinesText::new("Pair Code", pair_code),
            "HOLD BTN TO CONFIRM",
            "KEEP HOLDING...",
        ))
    }
}

pub struct GenericTwoLinePage<'s>(ConfirmBarPage<'s, TwoLinesText<'s, 's>>);
impl_wrapper_page!(
    GenericTwoLinePage<'s>,
    ConfirmBarPage<'s, TwoLinesText<'s, 's>>
);
impl<'s> GenericTwoLinePage<'s> {
    pub fn new(small: &'s str, large: &'s str, confirm_text: &'s str, threshold: u32) -> Self {
        GenericTwoLinePage(ConfirmBarPage::new_default_bar(
            threshold,
            TwoLinesText::new(small, large),
            &confirm_text,
            "KEEP HOLDING...",
        ))
    }
}

pub struct ShowScrollingAddressContent<'s> {
    address: &'s str,
    message: &'s str,
    iteration: usize,
}

impl<'s> ShowScrollingAddressContent<'s> {
    fn new(address: &'s str, message: &'s str) -> Self {
        ShowScrollingAddressContent {
            address,
            message,
            iteration: 0,
        }
    }
}

impl<'s> MainContent for ShowScrollingAddressContent<'s> {
    fn draw_to<T>(&self, target: &mut T) -> Result<(), <T as DrawTarget>::Error>
    where
        T: DrawTarget<Color = BinaryColor>,
    {
        let screen_size = target.bounding_box();
        let rectangle = Rectangle::new(Point::new(0, 22), Size::new(screen_size.size.width, 14))
            .into_styled(PrimitiveStyle::with_fill(Off));
        rectangle.draw(target)?;

        let value_text = Text::with_text_style(
            &self.message,
            Point::new(64, 10),
            MonoTextStyle::new(&ascii::FONT_6X10, On),
            TextStyleBuilder::new()
                .alignment(Alignment::Center)
                .baseline(Baseline::Top)
                .build(),
        );
        value_text.draw(target)?;

        let scroll = ScrollText::<1, 5, 15>::new(self.address);

        let address_text = Text::with_text_style(
            scroll.compute(self.iteration),
            Point::new(64, 22),
            MonoTextStyle::new(&ascii::FONT_8X13_BOLD, On),
            TextStyleBuilder::new()
                .alignment(Alignment::Center)
                .baseline(Baseline::Top)
                .build(),
        );
        address_text.draw(target)?;

        Ok(())
    }

    fn tick(&mut self) -> bool {
        self.iteration += 1;
        true
    }
}

pub struct ShowScrollingAddressPage<'s>(ConfirmBarPage<'s, ShowScrollingAddressContent<'s>>);
impl_wrapper_page!(
    ShowScrollingAddressPage<'s>,
    ConfirmBarPage<'s, ShowScrollingAddressContent<'s>>
);
impl<'s> ShowScrollingAddressPage<'s> {
    pub fn new(address: &'s str, message: &'s str, bar_message: &'static str) -> Self {
        ShowScrollingAddressPage(ConfirmBarPage::new_default_bar(
            100,
            ShowScrollingAddressContent::new(address, message),
            bar_message,
            "KEEP HOLDING...",
        ))
    }
}

pub struct TxSummaryPageContent {
    fees: Amount,
}
impl MainContent for TxSummaryPageContent {
    fn draw_to<T>(&self, target: &mut T) -> Result<(), <T as DrawTarget>::Error>
    where
        T: DrawTarget<Color = BinaryColor>,
    {
        let fees_str = alloc::format!("{:.8} BTC", self.fees.display_in(Denomination::Bitcoin));
        let content = TwoLinesText::new("Transaction Fee", &fees_str);
        content.draw_to(target)
    }
}
pub struct TxSummaryPage(ConfirmBarPage<'static, TxSummaryPageContent>);
impl_wrapper_page!(TxSummaryPage, ConfirmBarPage<'static, TxSummaryPageContent>);
impl TxSummaryPage {
    pub fn new(fees: Amount) -> Self {
        TxSummaryPage(ConfirmBarPage::new_default_bar(
            80,
            TxSummaryPageContent { fees },
            "HOLD BTN TO SIGN TX",
            "KEEP HOLDING...",
        ))
    }
}

pub struct MnemonicPageContent<'w, 'l> {
    offset: u8,
    words: &'l [&'w str],
}
impl<'w, 'l> MainContent for MnemonicPageContent<'w, 'l> {
    fn draw_to<T>(&self, target: &mut T) -> Result<(), <T as DrawTarget>::Error>
    where
        T: DrawTarget<Color = BinaryColor>,
    {
        let number_font = MonoTextStyle::new(&ascii::FONT_6X10, On);
        let word_font = MonoTextStyle::new(&ascii::FONT_8X13_BOLD, On);
        let number_style = TextStyleBuilder::new()
            .alignment(Alignment::Right)
            .baseline(Baseline::Bottom)
            .build();
        let word_style = TextStyleBuilder::new()
            .alignment(Alignment::Center)
            .baseline(Baseline::Bottom)
            .build();

        const WORDS_POSITION: [Point; 2] = [Point::new(18, 18), Point::new(18, 34)];

        let mut draw_word = |i, w| -> Result<(), <T as DrawTarget>::Error> {
            let text = alloc::format!("{}.", i as u8 + self.offset + 1);
            Text::with_text_style(&text, WORDS_POSITION[i], number_font, number_style)
                .draw(target)?;
            Text::with_text_style(
                w,
                WORDS_POSITION[i] + Point::new((128 - 20) / 2, 0),
                word_font,
                word_style,
            )
            .draw(target)?;
            Ok(())
        };

        for (index, word) in self.words.iter().enumerate().take(WORDS_POSITION.len()) {
            draw_word(index, word)?;
        }

        Ok(())
    }
}
pub struct MnemonicPage<'w, 'l>(ConfirmBarPage<'static, MnemonicPageContent<'w, 'l>>);
impl_wrapper_page!(
    MnemonicPage<'w, 'l>,
    ConfirmBarPage<'static, MnemonicPageContent<'w, 'l>>
);
impl<'w, 'l> MnemonicPage<'w, 'l> {
    pub fn new(offset: u8, words: &'l [&'w str]) -> Self {
        MnemonicPage(ConfirmBarPage::new_default_bar(
            50,
            MnemonicPageContent { words, offset },
            "HOLD BTN TO CONTINUE",
            "KEEP HOLDING...",
        ))
    }
}

#[derive(Debug)]
pub struct FwUpdatePage {
    progress: usize,
}

impl FwUpdatePage {
    pub fn new() -> Self {
        FwUpdatePage { progress: 0 }
    }

    pub fn add_progress(&mut self, value: usize) {
        self.progress += value
    }

    pub fn is_done(&self) -> bool {
        self.progress >= 100
    }
}

impl Page for FwUpdatePage {
    fn draw_to<T>(&self, target: &mut T) -> Result<(), <T as DrawTarget>::Error>
    where
        T: DrawTarget<Color = BinaryColor>,
    {
        let screen_size = target.bounding_box();

        let text = Text::with_text_style(
            "UPDATE IN PROGRESS",
            screen_size.center(),
            MonoTextStyle::new(&ascii::FONT_5X8, On),
            TextStyleBuilder::new()
                .alignment(Alignment::Center)
                .baseline(Baseline::Middle)
                .build(),
        );
        text.draw(target)?;

        let progress_bar = Rectangle::new(
            Point::new(0, (screen_size.size.height - 4) as i32),
            Size::new(screen_size.size.width * self.progress as u32 / 100, 4),
        )
        .into_styled(PrimitiveStyle::with_fill(On));
        progress_bar.draw(target)?;

        Ok(())
    }
}

#[derive(Debug)]
pub struct ErrorPage<'s> {
    message: &'s str,
}

impl<'s> ErrorPage<'s> {
    pub fn new(message: &'s str) -> Self {
        Self { message }
    }
}

impl<'s> Page for ErrorPage<'s> {
    fn draw_to<T>(&self, target: &mut T) -> Result<(), <T as DrawTarget>::Error>
    where
        T: DrawTarget<Color = BinaryColor>,
    {
        let screen_size = target.bounding_box();

        let text = Text::with_text_style(
            "ERROR\nTRY AGAIN",
            screen_size.center() - Point::new(0, 16),
            MonoTextStyle::new(&ascii::FONT_6X10, On),
            TextStyleBuilder::new()
                .alignment(Alignment::Center)
                .baseline(Baseline::Middle)
                .build(),
        );
        text.draw(target)?;

        let text = Text::with_text_style(
            self.message,
            screen_size.center() + Point::new(0, 12),
            MonoTextStyle::new(&ascii::FONT_5X8, On),
            TextStyleBuilder::new()
                .alignment(Alignment::Center)
                .baseline(Baseline::Middle)
                .build(),
        );
        text.draw(target)?;

        Ok(())
    }
}
