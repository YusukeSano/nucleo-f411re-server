use crate::{util, Error, Result};

#[derive(Copy, Clone)]
pub enum Http<'a> {
    Raw(&'a [u8]),
}

pub struct HttpPdu {
    buffer: [u8; 1460],
    inner_size: usize,
}

impl HttpPdu {
    pub fn new() -> Self {
        HttpPdu {
            buffer: [0u8; 1460],
            inner_size: 0,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.buffer[..self.computed_ihl() + self.inner_size]
    }

    fn get_header(&self) -> &[u8] {
        let str = core::str::from_utf8(&self.buffer).unwrap();
        if let Some(body_start) = str.find("\n\n") {
            str[..body_start + 2].as_bytes()
        } else if let Some(body_start) = str.find("\r\n\r\n") {
            str[..body_start + 4].as_bytes()
        } else {
            &[]
        }
    }

    fn computed_ihl(&self) -> usize {
        self.get_header().len()
    }

    pub fn inner(&mut self, value: &[u8]) -> Result<()> {
        let len = value.len();
        let header = "HTTP/1.1 200 OK\r\ncontent-type: text/html\r\ncontent-length: ".as_bytes();
        self.buffer[..header.len()].copy_from_slice(header);
        let tmp = util::usize_to_bytes(len);
        let content_length = &tmp[4 - util::get_digit_from_usize(len) as usize..tmp.len()];
        let content_length_index = header.len() + content_length.len();
        self.buffer[header.len()..content_length_index].copy_from_slice(content_length);
        self.buffer[content_length_index..content_length_index + 4]
            .copy_from_slice("\r\n\r\n".as_bytes());

        let ihl = self.computed_ihl();
        if len > 1460 - ihl {
            return Err(Error::Oversized);
        }
        self.inner_size = len;
        self.buffer[ihl..ihl + len].copy_from_slice(value);
        Ok(())
    }
}

#[derive(Copy, Clone)]
pub struct HttpParser<'a> {
    buffer: &'a [u8],
}

impl<'a> HttpParser<'a> {
    pub fn parse(buffer: &'a [u8]) -> Result<Self> {
        Ok(HttpParser { buffer })
    }

    pub fn inner(&'a self) -> Result<Http<'a>> {
        self.clone().into_inner()
    }

    pub fn into_inner(self) -> Result<Http<'a>> {
        let str = core::str::from_utf8(self.buffer).unwrap();
        if let Some(body_start) = str.find("\n\n") {
            Ok(Http::Raw(str[(body_start + 2)..].as_bytes()))
        } else if let Some(body_start) = str.find("\r\n\r\n") {
            Ok(Http::Raw(str[(body_start + 4)..].as_bytes()))
        } else {
            Ok(Http::Raw(&[]))
        }
    }

    pub fn header(&'a self) -> &[u8] {
        let str = core::str::from_utf8(self.buffer).unwrap();
        if let Some(body_start) = str.find("\n\n") {
            str[..body_start + 2].as_bytes()
        } else if let Some(body_start) = str.find("\r\n\r\n") {
            str[..body_start + 4].as_bytes()
        } else {
            &[]
        }
    }

    pub fn method(&'a self) -> Option<&str> {
        match self.buffer[0..=3] {
            [0x47, 0x45, 0x54, 0x20] => Some("GET"),
            [0x50, 0x4F, 0x53, 0x54] => Some("POST"),
            _ => None,
        }
    }
}
