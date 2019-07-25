use crate::{Error, GlobalHeader, PcapRecords};
use log::*;

pub struct CaptureFile<'a> {
    pub global_header: GlobalHeader,
    pub records: PcapRecords<'a>,
}

impl<'a> CaptureFile<'a> {
    ///
    /// Parse a slice of bytes that start with libpcap file format header (https://wiki.wireshark.org/Development/LibpcapFileFormat)
    ///
    pub fn parse<'b>(
        input: &'b [u8],
    ) -> Result<(&'b [u8], CaptureFile<'b>), Error>
    {
        let (rem, header) = GlobalHeader::parse(input)?;

        debug!(
            "Global header version {}.{}, with endianness {:?}",
            header.version_major,
            header.version_minor,
            header.endianness
        );

        let (records_rem, records) = PcapRecords::parse(rem, header.endianness)?;

        trace!("{} bytes left for record parsing", records_rem.len());

        Ok( (records_rem, CaptureFile {
            global_header: header,
            records: records,
        }) )
    }
}