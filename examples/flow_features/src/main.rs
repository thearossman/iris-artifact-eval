use clap::Parser;
use iris_compiler::*;
use iris_core::{config::load_config, L4Pdu, Runtime};
use std::path::PathBuf;

#[derive(Parser, Debug)]
struct Args {
    #[clap(
        short,
        long,
        parse(from_os_str),
        value_name = "FILE",
        default_value = "./configs/offline.toml"
    )]
    config: PathBuf,
    // ... other command line arguments
}

/*
 * An Iris datatype is defined using #[datatype] syntax.
 * One of these structs will be initialized per connection
 * (i.e., you can use this struct to maintain per-connection state).
 * (Note: you could alternatively define this as a callback, especially
 * if you wanted to filter.)
 */
#[derive(Debug, Clone)]
#[datatype("level=L4Terminated")]
pub struct ConnVolume {
    // ... fields to store data
}

impl ConnVolume {
    /* PDU is a required argument. */
    pub fn new(_pdu: &L4Pdu) -> Self {
        ConnVolume {
            // ... initialize data
        }
    }

    /* `level=L4InPayload` indicates that this should be invoked on every new packet */
    #[datatype_group("ConnVolume,level=L4InPayload")]
    pub fn new_packet(&mut self, _pdu: &L4Pdu) {
        // ... update stored data
    }
}

/*
 * An Iris callback is defined using #[callback] syntax with two inputs: "filter,level"
 * This will be invoked when the connection terminates.
 * Note: buggy when filter is empty; just do `tcp or udp` for now.
 */
#[callback("tcp or udp,level=L4Terminated")]
pub fn record_data(_conn: &ConnVolume) {
    // ... body (e.g., record data)
}

/*
 * Note: if you want to use the data types in the datatypes/ crate, you need to:
 * - Build `datatypes` with `skip_expand` feature disabled
 * - Add this macro to `main`: #[input_files("$IRIS_HOME/datatypes/data.txt")]
 */
#[iris_main]
fn main() {
    env_logger::init();
    let args = Args::parse();
    let config = load_config(&args.config);
    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();
}
