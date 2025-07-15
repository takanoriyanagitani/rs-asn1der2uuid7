use std::io;
use std::io::Write;
use std::process::ExitCode;

use rs_asn1der2uuid7::new_raw_uuid_v7_asn1_now;

fn now2uuid2asn1() -> Result<Vec<u8>, io::Error> {
    let asn1_uuid = new_raw_uuid_v7_asn1_now()?;
    asn1_uuid.to_der_bytes()
}

fn der2writer(der_bytes: &[u8], writer: &mut impl Write) -> Result<(), io::Error> {
    writer.write_all(der_bytes)?;
    Ok(())
}

fn der2stdout(der_bytes: &[u8]) -> Result<(), io::Error> {
    der2writer(der_bytes, &mut io::stdout())
}

fn main() -> ExitCode {
    match now2uuid2asn1() {
        Ok(der_bytes) => {
            der2stdout(&der_bytes).expect("Failed to write to stdout");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            ExitCode::FAILURE
        }
    }
}
