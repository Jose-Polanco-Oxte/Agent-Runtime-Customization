use anyhow::{Context, Result};
use serde::Serialize;

#[derive(Serialize)]
struct SkillFrontmatter<'a> {
    name: &'a str,
    description: &'a str,
}

/// Render provider metadata as YAML strings and preserve the source body bytes.
pub(super) fn render_skill_document(
    name: &str,
    description: &str,
    content: &str,
) -> Result<String> {
    let metadata = yaml_serde::to_string(&SkillFrontmatter { name, description })
        .context("failed to serialize skill frontmatter")?;
    let mut document = format!("---\n{metadata}---\n\n");
    document.push_str(strip_initial_frontmatter(content));
    Ok(document)
}

fn strip_initial_frontmatter(content: &str) -> &str {
    let Some(rest) = content
        .strip_prefix("---\n")
        .or_else(|| content.strip_prefix("---\r\n"))
    else {
        return content;
    };

    let mut offset = content.len() - rest.len();
    for line in rest.split_inclusive('\n') {
        offset += line.len();
        let text = line.strip_suffix('\n').unwrap_or(line);
        let text = text.strip_suffix('\r').unwrap_or(text);
        if text == "---" {
            return &content[offset..];
        }
    }
    // An opening marker alone is not a complete block. Keep all source text.
    content
}
