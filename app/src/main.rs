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

    // Random Number Generator
    let mut rng = Xorshift32::new(0xFF);

    // TCP
    let mut tcp_state: TcpState = TcpState::Closed;

    loop {
        let mut buffer = [0u8; 1522];
        if tcp_state == TcpState::Closed {
            tcp_state = TcpState::Listen;
        }
        let len = enc28j60.receive(&mut buffer).unwrap();

        match EthernetParser::parse(&buffer[..len as usize]) {
            Ok(ethernet_rcvd) => match ethernet_rcvd.inner() {
                Ok(Ethernet::Arp(arp_rcvd)) => {
                    if arp_rcvd.opcode() == ArpOpcode::REQUEST
                        && arp_rcvd.target_protocol_address() == IP
                    {
                        let mut arp_pdu = ArpPdu::new();
                        arp_pdu.opcode(ArpOpcode::REPLY);
                        arp_pdu.sender_hardware_address(MAC);
                        arp_pdu.sender_protocol_address(IP);
                        arp_pdu.target_hardware_address(arp_rcvd.sender_hardware_address());
                        arp_pdu.target_protocol_address(arp_rcvd.sender_protocol_address());

                        let mut ethernet_pdu = EthernetPdu::new(EtherType::ARP);
                        ethernet_pdu.destination_address(ethernet_rcvd.source_address());
                        ethernet_pdu.source_address(MAC);
                        ethernet_pdu.inner(arp_pdu.as_bytes()).unwrap();

                        enc28j60.transmit(ethernet_pdu.as_bytes()).unwrap();
                    }
                }
                Ok(Ethernet::Ipv4(ipv4_rcvd)) => match ipv4_rcvd.inner() {
                    Ok(Ipv4::Icmp(icmp_rcvd)) => {
                        if icmp_rcvd.message_type() == IcmpType::ECHO_REQUEST {
                            let mut icmp_pdu = IcmpPdu::new();
                            icmp_pdu.message_type(IcmpType::ECHO_REPLY);
                            match icmp_rcvd.inner() {
                                Ok(Icmp::Raw(raw_rcvd)) => {
                                    icmp_pdu.inner(raw_rcvd).unwrap();
                                }
                                _ => {}
                            }
                            icmp_pdu.compute_checksum();

                            let mut ipv4_pdu = Ipv4Pdu::new();
                            ipv4_pdu.protocol(IpProto::ICMP);
                            ipv4_pdu.source_address(ipv4_rcvd.destination_address());
                            ipv4_pdu.destination_address(ipv4_rcvd.source_address());
                            ipv4_pdu.inner(icmp_pdu.as_bytes()).unwrap();
                            ipv4_pdu.compute_checksum();

                            let mut ethernet_pdu = EthernetPdu::new(EtherType::IPV4);
                            ethernet_pdu.destination_address(ethernet_rcvd.source_address());
                            ethernet_pdu.source_address(ethernet_rcvd.destination_address());
                            ethernet_pdu.inner(ipv4_pdu.as_bytes()).unwrap();

                            enc28j60.transmit(ethernet_pdu.as_bytes()).unwrap();
                        }
                    }
                    Ok(Ipv4::Udp(udp_rcvd)) => {
                        let mut udp_pdu = UdpPdu::new();
                        udp_pdu.source_port(udp_rcvd.destination_port());
                        udp_pdu.destination_port(udp_rcvd.source_port());
                        match udp_rcvd.inner() {
                            Ok(Udp::Raw(raw_rcvd)) => {
                                udp_pdu.inner(raw_rcvd).unwrap();
                            }
                            _ => {}
                        }
                        udp_pdu.compute_checksum(&IpPseudoHeader::Ipv4(Ipv4PseudoHeader {
                            source_address: ipv4_rcvd.destination_address(),
                            destination_address: ipv4_rcvd.source_address(),
                            protocol: IpProto::UDP,
                        }));

                        let mut ipv4_pdu = Ipv4Pdu::new();
                        ipv4_pdu.protocol(IpProto::UDP);
                        ipv4_pdu.source_address(ipv4_rcvd.destination_address());
                        ipv4_pdu.destination_address(ipv4_rcvd.source_address());
                        ipv4_pdu.inner(udp_pdu.as_bytes()).unwrap();
                        ipv4_pdu.compute_checksum();

                        let mut ethernet_pdu = EthernetPdu::new(EtherType::IPV4);
                        ethernet_pdu.destination_address(ethernet_rcvd.source_address());
                        ethernet_pdu.source_address(ethernet_rcvd.destination_address());
                        ethernet_pdu.inner(ipv4_pdu.as_bytes()).unwrap();

                        enc28j60.transmit(ethernet_pdu.as_bytes()).unwrap();
                    }
                    Ok(Ipv4::Tcp(tcp_rcvd)) => match tcp_state {
                        TcpState::Listen => match tcp_rcvd.flags() {
                            TcpFlag::SYN => {
                                let mut tcp_pdu = TcpPdu::new();
                                tcp_pdu.source_port(tcp_rcvd.destination_port());
                                tcp_pdu.destination_port(tcp_rcvd.source_port());
                                tcp_pdu.sequence_number(rng.gen());
                                tcp_pdu.acknowledgement_number(tcp_rcvd.sequence_number() + 1);
                                tcp_pdu.syn(true);
                                tcp_pdu.ack(true);
                                tcp_pdu.compute_checksum(&IpPseudoHeader::Ipv4(Ipv4PseudoHeader {
                                    source_address: ipv4_rcvd.destination_address(),
                                    destination_address: ipv4_rcvd.source_address(),
                                    protocol: IpProto::TCP,
                                }));

                                let mut ipv4_pdu = Ipv4Pdu::new();
                                ipv4_pdu.protocol(IpProto::TCP);
                                ipv4_pdu.source_address(ipv4_rcvd.destination_address());
                                ipv4_pdu.destination_address(ipv4_rcvd.source_address());
                                ipv4_pdu.inner(tcp_pdu.as_bytes()).unwrap();
                                ipv4_pdu.compute_checksum();

                                let mut ethernet_pdu = EthernetPdu::new(EtherType::IPV4);
                                ethernet_pdu.destination_address(ethernet_rcvd.source_address());
                                ethernet_pdu.source_address(ethernet_rcvd.destination_address());
                                ethernet_pdu.inner(ipv4_pdu.as_bytes()).unwrap();

                                enc28j60.transmit(ethernet_pdu.as_bytes()).unwrap();
                                tcp_state = TcpState::SynReceived;
                            }
                            _ => {}
                        },
                        TcpState::SynReceived => match tcp_rcvd.flags() {
                            TcpFlag::ACK => {
                                tcp_state = TcpState::Established;
                                led.set_high();
                            }
                            _ => {}
                        },
                        TcpState::Established => match tcp_rcvd.flags() {
                            flag if flag == TcpFlag::PSH + TcpFlag::ACK => {
                                let mut tcp_pdu = TcpPdu::new();
                                tcp_pdu.source_port(tcp_rcvd.destination_port());
                                tcp_pdu.destination_port(tcp_rcvd.source_port());
                                tcp_pdu.sequence_number(tcp_rcvd.acknowledgement_number());
                                let data_length = ipv4_rcvd.total_length()
                                    - ipv4_rcvd.computed_ihl() as u16
                                    - tcp_rcvd.computed_data_offset() as u16;
                                tcp_pdu.acknowledgement_number(
                                    tcp_rcvd.sequence_number() + u32::from(data_length),
                                );
                                tcp_pdu.ack(true);
                                match tcp_rcvd.inner() {
                                    Ok(Tcp::Raw(raw_rcvd)) => match HttpParser::parse(raw_rcvd) {
                                        Ok(http_rcvd) => {
                                            if let Some(method) = http_rcvd.method() {
                                                if method == "GET" {
                                                    let mut http_pdu = HttpPdu::new();
                                                    http_pdu
                                                        .inner(
                                                            "<!DOCTYPE html>\r\n\
                                                            <html>\r\n\
                                                            <head>\r\n\
                                                            <title>HelloWorld!</title>\r\n\
                                                            <meta charset=\"utf-8\" />\r\n\
                                                            <link rel=\"icon\" href=\"data:,\">\r\n\
                                                            </head>\r\n\
                                                            <body>\r\n\
                                                            <h1>HelloWorld!</h1>\r\n\
                                                            </body>\r\n\
                                                            </html>"
                                                                .as_bytes(),
                                                        )
                                                        .unwrap();

                                                    tcp_pdu.psh(true);
                                                    tcp_pdu.inner(http_pdu.as_bytes()).unwrap();
                                                }
                                            }
                                        }
                                        _ => {}
                                    },
                                    _ => {}
                                }
                                tcp_pdu.compute_checksum(&IpPseudoHeader::Ipv4(Ipv4PseudoHeader {
                                    source_address: ipv4_rcvd.destination_address(),
                                    destination_address: ipv4_rcvd.source_address(),
                                    protocol: IpProto::TCP,
                                }));

                                let mut ipv4_pdu = Ipv4Pdu::new();
                                ipv4_pdu.protocol(IpProto::TCP);
                                ipv4_pdu.source_address(ipv4_rcvd.destination_address());
                                ipv4_pdu.destination_address(ipv4_rcvd.source_address());
                                ipv4_pdu.inner(tcp_pdu.as_bytes()).unwrap();
                                ipv4_pdu.compute_checksum();

                                let mut ethernet_pdu = EthernetPdu::new(EtherType::IPV4);
                                ethernet_pdu.destination_address(ethernet_rcvd.source_address());
                                ethernet_pdu.source_address(ethernet_rcvd.destination_address());
                                ethernet_pdu.inner(ipv4_pdu.as_bytes()).unwrap();

                                enc28j60.transmit(ethernet_pdu.as_bytes()).unwrap();
                            }
                            flag if flag == TcpFlag::FIN + TcpFlag::ACK => {
                                tcp_state = TcpState::CloseWait;

                                let mut tcp_pdu = TcpPdu::new();
                                tcp_pdu.source_port(tcp_rcvd.destination_port());
                                tcp_pdu.destination_port(tcp_rcvd.source_port());
                                tcp_pdu.sequence_number(tcp_rcvd.acknowledgement_number());
                                tcp_pdu.acknowledgement_number(tcp_rcvd.sequence_number() + 1);
                                tcp_pdu.fin(true);
                                tcp_pdu.ack(true);
                                tcp_pdu.compute_checksum(&IpPseudoHeader::Ipv4(Ipv4PseudoHeader {
                                    source_address: ipv4_rcvd.destination_address(),
                                    destination_address: ipv4_rcvd.source_address(),
                                    protocol: IpProto::TCP,
                                }));

                                let mut ipv4_pdu = Ipv4Pdu::new();
                                ipv4_pdu.protocol(IpProto::TCP);
                                ipv4_pdu.source_address(ipv4_rcvd.destination_address());
                                ipv4_pdu.destination_address(ipv4_rcvd.source_address());
                                ipv4_pdu.inner(tcp_pdu.as_bytes()).unwrap();
                                ipv4_pdu.compute_checksum();

                                let mut ethernet_pdu = EthernetPdu::new(EtherType::IPV4);
                                ethernet_pdu.destination_address(ethernet_rcvd.source_address());
                                ethernet_pdu.source_address(ethernet_rcvd.destination_address());
                                ethernet_pdu.inner(ipv4_pdu.as_bytes()).unwrap();

                                enc28j60.transmit(ethernet_pdu.as_bytes()).unwrap();
                                tcp_state = TcpState::LastAck;
                            }
                            _ => {}
                        },
                        TcpState::LastAck => match tcp_rcvd.flags() {
                            TcpFlag::ACK => {
                                tcp_state = TcpState::Closed;
                                led.set_low();
                            }
                            _ => {}
                        },
                        _ => {}
                    },
                    _ => {}
                },
                _ => {}
            },
            _ => {}
        }
    }
}
