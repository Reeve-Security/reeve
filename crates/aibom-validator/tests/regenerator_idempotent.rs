use std::path::PathBuf;
use std::process::Command;

fn assert_zero_git_diff(repo_root: &PathBuf, path: &str) {
    let diff = Command::new("git")
        .args(["diff", "--exit-code", path])
        .current_dir(repo_root)
        .status()
        .unwrap();
    assert!(
        diff.success(),
        "fixture regenerator produced a diff under {path}"
    );
}

#[test]
fn python_regenerator_produces_zero_git_diff() {
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .unwrap()
        .to_path_buf();

    let regen = Command::new("python3")
        .args(["schema/examples/tools/regenerate.py"])
        .current_dir(&repo_root)
        .status()
        .unwrap();
    assert!(regen.success());

    assert_zero_git_diff(&repo_root, "schema/examples/fixtures/");
    assert_zero_git_diff(&repo_root, "schema/examples/sensitive-data-report/");
    assert_zero_git_diff(&repo_root, "schema/examples/secret-rule-pack/");
}
