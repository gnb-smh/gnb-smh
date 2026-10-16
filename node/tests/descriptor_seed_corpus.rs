//! Keep the public-descriptor fuzzer's committed seeds meaningful on stable.
use gnb_crypto::wallet::descriptor::{public_request, request_from_json};

#[test]
fn descriptor_seed_corpus_accepts_controls_and_refuses_invalid_requests() {
    let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fuzz/corpus/descriptor_json");
    let (mut accepted, mut rejected) = (0, 0);
    for entry in std::fs::read_dir(directory).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name().to_str().unwrap().to_owned();
        let bytes = std::fs::read(entry.path()).unwrap();
        let result = request_from_json(&bytes).and_then(|request| public_request(&request));
        if name.starts_with("accept-") {
            assert!(result.is_ok(), "{name}: {:?}", result.err());
            accepted += 1;
        } else {
            assert!(name.starts_with("reject-"), "unclassified seed: {name}");
            assert!(result.is_err(), "invalid seed was accepted: {name}");
            rejected += 1;
        }
    }
    assert_eq!(accepted, 8);
    assert_eq!(rejected, 4);
}
