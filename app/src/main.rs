#![deny(unsafe_code)]
#![allow(clippy::empty_loop)]
#![no_main]
#![no_std]

use panic_halt as _;

use cortex_m_rt::entry;
use enc28j60::Enc28j60;
use pdu::*;
use stm32f4xx_hal::{pac::Peripherals, prelude::*, spi::Spi};

/* Configuration */
const MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x00];
const IP: [u8; 4] = [192, 168, 0, 1];

/* Constants */
const KB: u16 = 1024; // bytes

#[entry]
fn main() -> ! {
    let cp = cortex_m::peripheral::Peripherals::take().unwrap();
    let dp = Peripherals::take().unwrap();

    let rcc = dp.RCC.constrain();
    let mut clk = rcc.cfgr.freeze();

    // LED
    let gpiob = dp.GPIOB.split();
    let mut led = gpiob.pb5.into_push_pull_output();
    led.set_low();

    // SPI
    let gpioa = dp.GPIOA.split();
    let mut cs = gpioa.pa4.into_push_pull_output();
    cs.set_high();
    let sck = gpioa.pa5.into_alternate::<5>();
    let miso = gpioa.pa6.into_alternate::<5>();
    let mosi = gpioa.pa7.into_alternate::<5>();
    let spi = Spi::new(
        dp.SPI1,
        (sck, miso, mosi),
        enc28j60::MODE,
        1.MHz(),
        &mut clk,
    );

    // ENC28J60
    let mut delay = cp.SYST.delay(&clk);
    let mut enc28j60 = Enc28j60::new(
        spi,
        cs,
        enc28j60::Unconnected,
        enc28j60::Unconnected,
        &mut delay,
        7 * KB,
        MAC,
    )
    .unwrap();

    loop {
        let mut buffer = [0u8; 1522];
        let len = enc28j60.receive(&mut buffer).unwrap();

        if len != 0 {
            led.toggle();
        }
    }
}
