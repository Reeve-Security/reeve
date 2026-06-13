use anyhow::{Context, Result};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::time::timeout;

#[derive(Debug, Clone)]
pub struct McpLists {
    pub tools: Value,
    pub resources: Value,
    pub prompts: Value,
}

pub async fn list_stdio(
    command: &str,
    args: &[String],
    env: &BTreeMap<String, String>,
    timeout_seconds: u64,
) -> Result<McpLists> {
    let mut child = Command::new(command)
        .args(args)
        .envs(env)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("spawn MCP server {command}"))?;

    let mut stdin = child.stdin.take().context("missing child stdin")?;
    let stdout = child.stdout.take().context("missing child stdout")?;
    let mut lines = BufReader::new(stdout).lines();
    let deadline = Duration::from_secs(timeout_seconds.max(1));

    request(&mut stdin, 1, "initialize", json!({"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"reeve","version":"0.1.0"}})).await?;
    let _ = read_response(&mut lines, deadline).await?;
    request(&mut stdin, 2, "tools/list", json!({})).await?;
    let tools = read_response(&mut lines, deadline).await?;
    request(&mut stdin, 3, "resources/list", json!({})).await?;
    let resources = read_response(&mut lines, deadline)
        .await
        .unwrap_or_else(|_| json!({"resources":[]}));
    request(&mut stdin, 4, "prompts/list", json!({})).await?;
    let prompts = read_response(&mut lines, deadline)
        .await
        .unwrap_or_else(|_| json!({"prompts":[]}));

    let _ = child.kill().await;
    Ok(McpLists {
        tools,
        resources,
        prompts,
    })
}

async fn request(
    stdin: &mut tokio::process::ChildStdin,
    id: u64,
    method: &str,
    params: Value,
) -> Result<()> {
    let message = json!({"jsonrpc":"2.0","id":id,"method":method,"params":params});
    stdin
        .write_all(serde_json::to_string(&message)?.as_bytes())
        .await?;
    stdin.write_all(b"\n").await?;
    stdin.flush().await?;
    Ok(())
}

async fn read_response(
    lines: &mut tokio::io::Lines<BufReader<tokio::process::ChildStdout>>,
    deadline: Duration,
) -> Result<Value> {
    let line = timeout(deadline, lines.next_line())
        .await
        .context("MCP server timed out")??
        .context("MCP server closed stdout")?;
    let value: Value = serde_json::from_str(&line)?;
    Ok(value.pointer("/result").cloned().unwrap_or(value))
}
