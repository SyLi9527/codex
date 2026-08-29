use codex_rb_launch_guard::LaunchPolicyCandidateV1;
use codex_rb_launch_guard::validate_launch_policy;
use serde::Serialize;
use std::io::Read;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Outcome<'a> {
    status: &'a str,
    gate: &'a str,
}

fn main() {
    let args = std::env::args().collect::<Vec<_>>();
    if args.as_slice().get(1).map(String::as_str) != Some("--validate-unreachable")
        || args.len() != 2
    {
        write_outcome(
            Outcome {
                status: "denied",
                gate: "product-entry-unreachable",
            },
            64,
        );
    }

    let mut bytes = Vec::new();
    if std::io::stdin()
        .take(64 * 1024 + 1)
        .read_to_end(&mut bytes)
        .is_err()
        || bytes.len() > 64 * 1024
    {
        write_outcome(
            Outcome {
                status: "denied",
                gate: "invalid-authority-input",
            },
            65,
        );
    }
    let policy = match serde_json::from_slice::<LaunchPolicyCandidateV1>(&bytes) {
        Ok(policy) => policy,
        Err(_) => write_outcome(
            Outcome {
                status: "denied",
                gate: "invalid-authority-input",
            },
            65,
        ),
    };
    match validate_launch_policy(policy) {
        Ok(_) => write_outcome(
            Outcome {
                status: "validated-unarmed",
                gate: "live-identity-and-note-exec-not-proven",
            },
            78,
        ),
        Err(_) => write_outcome(
            Outcome {
                status: "denied",
                gate: "authority-verification-failed",
            },
            66,
        ),
    }
}

fn write_outcome(outcome: Outcome<'_>, code: i32) -> ! {
    let encoded = serde_json::to_string(&outcome)
        .unwrap_or_else(|_| "{\"status\":\"denied\",\"gate\":\"encoding-failed\"}".to_string());
    println!("{encoded}");
    std::process::exit(code);
}
