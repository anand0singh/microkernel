//! 16550A UART Serial Driver for x86_64 Bare-Metal Logging
//! Writes formatted kernel diagnostic logs directly to COM1 (Port 0x3F8).

use core::fmt::{self, Write};
use spin::Mutex;
use x86_64::instructions::port::Port;

const COM1_PORT: u16 = 0x3F8;

pub struct SerialPort {
    data: Port<u8>,
    ier: Port<u8>,
    fcr: Port<u8>,
    lcr: Port<u8>,
    mcr: Port<u8>,
    lsr: Port<u8>,
}

impl SerialPort {
    pub const unsafe fn new(base: u16) -> Self {
        Self {
            data: Port::new(base),
            ier: Port::new(base + 1),
            fcr: Port::new(base + 2),
            lcr: Port::new(base + 3),
            mcr: Port::new(base + 4),
            lsr: Port::new(base + 5),
        }
    }

    /// Initializes 16550A UART chip at 115200 baud, 8 data bits, no parity, 1 stop bit (8N1)
    pub fn init(&mut self) {
        unsafe {
            // Disable interrupts
            self.ier.write(0x00);
            // Enable DLAB (set baud rate divisor)
            self.lcr.write(0x80);
            // Set divisor to 1 (low byte: 0x01, high byte: 0x00) => 115200 baud
            self.data.write(0x01);
            self.ier.write(0x00);
            // 8 bits, no parity, one stop bit (8N1), clear DLAB
            self.lcr.write(0x03);
            // Enable FIFO, clear TX/RX queues, 14-byte threshold
            self.fcr.write(0xC7);
            // IRQs enabled, RTS/DSR set
            self.mcr.write(0x0B);
        }
    }

    /// Checks if transmitter holding register is empty (bit 5 of LSR)
    pub fn is_transmit_empty(&mut self) -> bool {
        unsafe { (self.lsr.read() & 0x20) != 0 }
    }

    /// Sends a single byte over serial port (spins until transmit buffer is ready)
    pub fn send_byte(&mut self, byte: u8) {
        while !self.is_transmit_empty() {
            core::hint::spin_loop();
        }
        unsafe {
            self.data.write(byte);
        }
    }

    /// Sends a byte string over serial port
    pub fn write_str(&mut self, s: &str) {
        for byte in s.bytes() {
            if byte == b'\n' {
                self.send_byte(b'\r');
            }
            self.send_byte(byte);
        }
    }
}

impl Write for SerialPort {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.write_str(s);
        Ok(())
    }
}

pub static SERIAL1: Mutex<SerialPort> = Mutex::new(unsafe { SerialPort::new(COM1_PORT) });

pub fn init_serial() {
    SERIAL1.lock().init();
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {
        $crate::arch::x86_64::serial::_print(format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! printk {
    () => ($crate::print!("\n"));
    ($($arg:tt)*) => ($crate::print!("{}\n", format_args!($($arg)*)));
}

#[doc(hidden)]
pub fn _print(args: fmt::Arguments) {
    use core::fmt::Write;
    let mut serial = SERIAL1.lock();
    let _ = serial.write_fmt(args);
}
