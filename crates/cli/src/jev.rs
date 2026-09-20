//! Thin command adapter for Jev advice, with an optional interactive view.
use please_core::CallerContext;
use please_judge::jev::{self, JevClient, JevRequest, Relation};
use std::io::Read;

pub(crate) fn read_bounded(path: &str, limit: usize) -> Result<Vec<u8>, &'static str> {
    let mut bytes = Vec::new();
    if path == "-" {
        std::io::stdin()
            .lock()
            .take(limit as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| "could not read standard input")?;
    } else {
        std::fs::File::open(path)
            .map_err(|_| "could not open input file")?
            .take(limit as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| "could not read input file")?;
    }
    if bytes.len() > limit {
        return Err("input exceeds the byte limit");
    }
    Ok(bytes)
}
fn unavailable(detail: &str) -> i32 {
    println!(
        "{}",
        serde_json::json!({"schema_version":jev::CONTRACT_VERSION,"authority":"advisory","relation":"indeterminate","error":detail})
    );
    2
}
pub fn run(args: &crate::args::JevArgs) -> i32 {
    #[cfg(feature = "tui")]
    {
        use std::io::IsTerminal;
        let bare = args.input.is_none()
            && args.context.is_none()
            && args.provenance.is_none()
            && !args.check
            && !args.request_only;
        if args.tui
            || args.preset.is_some()
            || args.view_advice.is_some()
            || (bare && std::io::stdin().is_terminal() && std::io::stdout().is_terminal())
        {
            return crate::jev_tui::run(args);
        }
    }
    if !args.check && (args.context.is_none() || args.provenance.is_none()) {
        eprintln!("plz clap: JSON advice requires --context and --provenance; use --tui for the interactive workspace");
        return 64;
    }
    let model = match args
        .model
        .clone()
        .map(Ok)
        .unwrap_or_else(jev::model_from_env)
    {
        Ok(value) => value,
        Err(detail) => return unavailable(detail),
    };
    if args.check {
        println!(
            "{}",
            serde_json::json!({"provider":"typesafe","endpoint":jev::ENDPOINT,"model":model,"credential_variable":"TYPESAFE_API_KEY","credential_configured":jev::credential_configured(),"authority":"advisory","network_request":false})
        );
        return 0;
    }
    let Some(path) = &args.context else {
        return unavailable("caller context file is required");
    };
    let Some(provenance) = args.provenance else {
        return unavailable("caller provenance is required");
    };
    let context_bytes = match read_bounded(&path.to_string_lossy(), jev::MAX_CONTEXT_BYTES) {
        Ok(v) => v,
        Err(e) => return unavailable(e),
    };
    let context: CallerContext = match serde_json::from_slice(&context_bytes) {
        Ok(v) => v,
        Err(_) => return unavailable("invalid caller context JSON"),
    };
    let input = match read_bounded(args.input.as_deref().unwrap_or("-"), jev::MAX_INPUT_BYTES) {
        Ok(v) => v,
        Err(e) => return unavailable(e),
    };
    let request = match JevRequest::assemble(&input, &context, provenance.into(), &model) {
        Ok(v) => v,
        Err(e) => return unavailable(e),
    };
    if args.request_only {
        println!("{}", request.body());
        return 0;
    }
    let client = match JevClient::from_env() {
        Ok(v) => v,
        Err(e) => return unavailable(e),
    };
    match client.evaluate(&request) {
        Ok(advice) => {
            let code = match advice.relation {
                Relation::ConflictingInstruction => 1,
                Relation::Indeterminate => 2,
                _ => 3,
            };
            println!(
                "{}",
                serde_json::to_string(&advice).expect("finite validated advice")
            );
            code
        }
        Err(error) => unavailable(&error),
    }
}
