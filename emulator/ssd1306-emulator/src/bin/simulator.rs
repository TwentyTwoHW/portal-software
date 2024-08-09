use tokio::{io, net::UnixStream};

use ssd1306_emulator::{CommandStream, SRAM};

#[tokio::main]
async fn main() -> io::Result<()> {
    let mut sram = SRAM::default();

    let socket =
        UnixStream::connect(std::env::args().skip(1).next().expect("Socket argument")).await?;
    let mut command_stream = CommandStream(socket);

    let sdl_context = sdl2::init().unwrap();
    let video_subsystem = sdl_context.video().unwrap();

    let window = video_subsystem
        .window("SSD1306", 128 * 4, 64 * 4)
        .position_centered()
        .build()
        .unwrap();

    let mut canvas = window.into_canvas().build().unwrap();
    canvas.set_scale(4.0, 4.0).unwrap();
    canvas.set_draw_color(sdl2::pixels::Color::BLACK);
    canvas.clear();

    canvas.present();
    let mut event_pump = sdl_context.event_pump().unwrap();

    'running: loop {
        let update = command_stream.update_sram(&mut sram).await?;
        if update {
            sram.draw(&mut canvas).expect("Draw works");
        }

        for event in event_pump.poll_iter() {
            match event {
                sdl2::event::Event::Quit { .. }
                | sdl2::event::Event::KeyDown {
                    keycode: Some(sdl2::keyboard::Keycode::Escape),
                    ..
                } => {
                    break 'running;
                }
                _ => {}
            }
        }

        canvas.present();
    }

    Ok(())
}
