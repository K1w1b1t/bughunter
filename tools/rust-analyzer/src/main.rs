use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    let target = if args.len() > 1 { &args[1] } else { "" };
    let mut score: i32 = 10;
    if target.contains("api") {
        score += 20;
    }
    if target.contains("admin") {
        score += 30;
    }
    let out = serde_json::json!({
        "module": "rust_analyzer",
        "target": target,
        "high_speed_risk_hint": score
    });
    println!("{}", out.to_string());
}
